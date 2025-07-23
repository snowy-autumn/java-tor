package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.crypto.KeyPair;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.hs.IntroductionPoint;
import snowy.autumn.tor.relay.Handshakes;

import java.nio.ByteBuffer;

public class Extend2Command extends RelayCell {

    KeyPair temporaryKeyPair;

    byte[] linkSpecifiers;
    byte[] identityKey;
    byte[] ntorOnionKey;
    short handshakeType;
    byte[] mac;

    private Extend2Command(int circuitId, short handshakeType) {
        super(circuitId, true, EXTEND2, (short) 0);
        if (handshakeType != Handshakes.NTOR && handshakeType != Handshakes.NTORv3)
            throw new Error("Invalid / unsupported handshake type `"  + handshakeType + "`.");
        this.handshakeType = handshakeType;
    }

    public Extend2Command(int circuitId, RouterMicrodesc routerMicrodesc, short handshakeType) {
        this(circuitId, handshakeType);
        this.linkSpecifiers = routerMicrodesc.generateLinkSpecifiers();
        this.identityKey = handshakeType == Handshakes.NTOR ? routerMicrodesc.getFingerprint() : routerMicrodesc.getEd25519Id();
        this.ntorOnionKey = routerMicrodesc.getNtorOnionKey();
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
    }

    public Extend2Command(int circuitId, IntroductionPoint introductionPoint) {
        this(circuitId, introductionPoint.ed25519Id() == null ? Handshakes.NTOR : Handshakes.NTORv3);
        this.linkSpecifiers = introductionPoint.linkSpecifiers();
        this.identityKey = handshakeType == Handshakes.NTOR ? introductionPoint.fingerprint() : introductionPoint.ed25519Id();
        this.ntorOnionKey = introductionPoint.ntorOnionKey();
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
    }

    @Override
    protected byte[] serialiseRelayBody() {
        byte[] handshakeBlock = new byte[0];
        if (handshakeType == Handshakes.NTOR)
            handshakeBlock = Handshakes.generateNtorBlock(identityKey, ntorOnionKey, temporaryKeyPair);
        else if (handshakeType == Handshakes.NTORv3) {
            byte[][] ntorV3Block = Handshakes.generateNtorV3Block(identityKey, ntorOnionKey, temporaryKeyPair, new byte[1]);
            handshakeBlock = ntorV3Block[0];
            mac = ntorV3Block[1];
        }
        ByteBuffer buffer = ByteBuffer.allocate(linkSpecifiers.length + 2 + 2 + handshakeBlock.length);
        // Link specifiers
        buffer.put(linkSpecifiers);
        // Handshake type
        buffer.putShort(handshakeType);
        // The length of the handshake data
        buffer.putShort((short) handshakeBlock.length);
        // Handshake data
        buffer.put(handshakeBlock);

        return buffer.array();
    }

    public KeyPair getKeyPair() {
        return temporaryKeyPair;
    }

    public byte[] getMac() {
        return mac;
    }
}
