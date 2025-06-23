package snowy.autumn.tor.cell.cells;

import com.google.crypto.tink.hybrid.internal.X25519.KeyPair;
import com.google.crypto.tink.subtle.X25519;
import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.crypto.Keys;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class Create2Cell extends Cell {

    public static final short NTOR = 2;
    KeyPair temporaryKeyPair;
    byte[] fingerprint;
    byte[] ntorOnionKey;

    public Create2Cell(int circuitId, RouterMicrodesc microdesc) {
        super(circuitId, CREATE2);
        byte[] privateKey = X25519.generatePrivateKey();
        try {
            temporaryKeyPair = new KeyPair(privateKey, X25519.publicFromPrivate(privateKey));
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        this.fingerprint = microdesc.getFingerprint();
        this.ntorOnionKey = microdesc.getNtorOnionKey();
    }

    private byte[] generateNtorBlock() {
        return ByteBuffer.allocate(fingerprint.length + ntorOnionKey.length + temporaryKeyPair.publicKey.length)
                .put(fingerprint)
                .put(ntorOnionKey)
                .put(temporaryKeyPair.publicKey)
                .array();
    }

    @Override
    protected byte[] serialiseBody() {
        byte[] ntorBlock = generateNtorBlock();
        ByteBuffer buffer = ByteBuffer.allocate(2 + 2 + ntorBlock.length);
        // Handshake type
        buffer.putShort(NTOR);
        // The length of the handshake data
        buffer.putShort((short) ntorBlock.length);
        // Handshake data
        buffer.put(ntorBlock);

        return buffer.array();
    }

    public byte[] getPrivateKey() {
        return temporaryKeyPair.privateKey;
    }

    public Keys finishNtorHandshake(Created2Cell created2Cell) {
        return Cryptography.NTOR_KDF_RFC5869(temporaryKeyPair.privateKey, temporaryKeyPair.publicKey, ntorOnionKey, fingerprint, created2Cell.getPublicKey(), created2Cell.getAuth());
    }

}
