package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.crypto.KeyPair;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Handshakes;

import java.nio.ByteBuffer;

public class Create2Cell extends Cell {

    KeyPair temporaryKeyPair;
    byte[] identityKey;
    byte[] ntorOnionKey;
    short handshakeType;
    byte[] mac;

    public Create2Cell(int circuitId, RouterMicrodesc microdesc, short handshakeType) {
        super(circuitId, CREATE2);
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
        if (handshakeType != Handshakes.NTOR && handshakeType != Handshakes.NTORv3)
            throw new Error("Invalid / unsupported handshake type `"  + handshakeType + "`.");
        this.identityKey = handshakeType == Handshakes.NTOR ? microdesc.getFingerprint() : microdesc.getEd25519Id();
        this.ntorOnionKey = microdesc.getNtorOnionKey();
        this.handshakeType = handshakeType;
    }

    @Override
    protected byte[] serialiseBody() {
        byte[] handshakeBlock = new byte[0];
        if (handshakeType == Handshakes.NTOR)
            handshakeBlock = Handshakes.generateNtorBlock(identityKey, ntorOnionKey, temporaryKeyPair);
        else if (handshakeType == Handshakes.NTORv3) {
            byte[][] ntorV3Block = Handshakes.generateNtorV3Block(identityKey, ntorOnionKey, temporaryKeyPair, new byte[1]);
            handshakeBlock = ntorV3Block[0];
            mac = ntorV3Block[1];
        }

        ByteBuffer buffer = ByteBuffer.allocate(2 + 2 + handshakeBlock.length);
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
