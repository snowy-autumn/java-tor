package snowy.autumn.tor.cell.cells;

import com.google.crypto.tink.hybrid.internal.X25519.KeyPair;
import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Handshakes;

import java.nio.ByteBuffer;

public class Create2Cell extends Cell {

    KeyPair temporaryKeyPair;
    byte[] fingerprint;
    byte[] ntorOnionKey;

    public Create2Cell(int circuitId, RouterMicrodesc microdesc) {
        super(circuitId, CREATE2);
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
        this.fingerprint = microdesc.getFingerprint();
        this.ntorOnionKey = microdesc.getNtorOnionKey();
    }

    @Override
    protected byte[] serialiseBody() {
        byte[] ntorBlock = Handshakes.generateNtorBlock(fingerprint, ntorOnionKey, temporaryKeyPair);
        ByteBuffer buffer = ByteBuffer.allocate(2 + 2 + ntorBlock.length);
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
