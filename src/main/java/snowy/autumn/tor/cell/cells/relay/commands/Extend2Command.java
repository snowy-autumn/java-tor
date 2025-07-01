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
    byte[] fingerprint;
    byte[] ntorOnionKey;

    public Extend2Command(int circuitId, RouterMicrodesc routerMicrodesc) {
        super(circuitId, true, EXTEND2, (short) 0);
        this.linkSpecifiers = routerMicrodesc.generateLinkSpecifiers();
        this.fingerprint = routerMicrodesc.getFingerprint();
        this.ntorOnionKey = routerMicrodesc.getNtorOnionKey();
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
    }

    public Extend2Command(int circuitId, IntroductionPoint introductionPoint) {
        super(circuitId, true, EXTEND2, (short) 0);
        this.linkSpecifiers = introductionPoint.linkSpecifiers();
        this.fingerprint = introductionPoint.fingerprint();
        this.ntorOnionKey = introductionPoint.ntorOnionKey();
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
    }

    @Override
    protected byte[] serialiseRelayBody() {
        byte[] ntorBlock = Handshakes.generateNtorBlock(fingerprint, ntorOnionKey, temporaryKeyPair);
        ByteBuffer buffer = ByteBuffer.allocate(linkSpecifiers.length + 2 + 2 + ntorBlock.length);
        // Link specifiers
        buffer.put(linkSpecifiers);
        // Handshake type
        buffer.putShort(Handshakes.NTOR);
        // The length of the handshake data
        buffer.putShort((short) ntorBlock.length);
        // Handshake data
        buffer.put(ntorBlock);

        return buffer.array();
    }

    public KeyPair getKeyPair() {
        return temporaryKeyPair;
    }
}
