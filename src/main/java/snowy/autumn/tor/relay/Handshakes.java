package snowy.autumn.tor.relay;

import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.crypto.KeyPair;
import snowy.autumn.tor.crypto.Keys;

import java.nio.ByteBuffer;

public class Handshakes {

    public static final short NTOR = 2;

    public static byte[] generateNtorBlock(byte[] fingerprint, byte[] ntorOnionKey, KeyPair temporaryKeyPair) {
        return ByteBuffer.allocate(fingerprint.length + ntorOnionKey.length + temporaryKeyPair.publicKey().length)
                .put(fingerprint)
                .put(ntorOnionKey)
                .put(temporaryKeyPair.publicKey())
                .array();
    }

    public static Keys finishNtorHandshake(byte[] ntorOnionKey, byte[] fingerprint, KeyPair keyPair, byte[] relayPublicKey, byte[] auth) {
        return Cryptography.NTOR_KDF_RFC5869(keyPair.privateKey(), keyPair.publicKey(), ntorOnionKey, fingerprint, relayPublicKey, auth);
    }

}
