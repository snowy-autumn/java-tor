package snowy.autumn.tor.relay;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.crypto.KeyPair;
import snowy.autumn.tor.crypto.Keys;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

import static snowy.autumn.tor.crypto.Cryptography.*;

public class Handshakes {

    public static final short NTOR = 2;
    public static final short NTORv3 = 3;

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

    public static byte[][] generateNtorV3Block(byte[] ed25519Id, byte[] ntorOnionKey, KeyPair temporaryKeyPair, byte[] message) {
        byte[] Bx = Cryptography.computeSharedSecret(temporaryKeyPair.privateKey(), ntorOnionKey);
        byte[] secretInputPhase1 = ByteBuffer.allocate(Bx.length + ed25519Id.length + temporaryKeyPair.publicKey().length + ntorOnionKey.length + NTORv3_PROTOID.length() + NTORv3_VER_ENCAP.length)
                .put(Bx)
                .put(ed25519Id)
                .put(temporaryKeyPair.publicKey())
                .put(ntorOnionKey)
                .put(NTORv3_PROTOID.getBytes())
                .put(NTORv3_VER_ENCAP)
                .array();
        SHAKEDigest shakeDigest = new SHAKEDigest(256);
        shakeDigest.update(NTORv3_t_msgkdf_ENCAP, 0, NTORv3_t_msgkdf_ENCAP.length);
        shakeDigest.update(secretInputPhase1, 0, secretInputPhase1.length);

        byte[] encryptionKey = new byte[CIPHER_KEY_LENGTH];
        byte[] macKey = new byte[MAC_KEY_LENGTH];
        shakeDigest.doOutput(encryptionKey, 0, encryptionKey.length);
        shakeDigest.doOutput(macKey, 0, macKey.length);

        byte[] encryptedMessage;

        try {
            encryptedMessage = Cryptography.createAesKey(Cipher.ENCRYPT_MODE, encryptionKey).doFinal(message);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }

        // MAC
        MessageDigest sha3_256 = Cryptography.createDigest("SHA3-256", NTORv3_t_msgmac_ENCAP);
        sha3_256.update(ENCAP(macKey));
        sha3_256.update(
                ByteBuffer.allocate(ed25519Id.length + ntorOnionKey.length + temporaryKeyPair.publicKey().length + encryptedMessage.length)
                        .put(ed25519Id)
                        .put(ntorOnionKey)
                        .put(temporaryKeyPair.publicKey())
                        .put(encryptedMessage)
                        .array()
        );

        byte[] mac = sha3_256.digest();

        return new byte[][]{ByteBuffer.allocate(ed25519Id.length + ntorOnionKey.length + temporaryKeyPair.publicKey().length + encryptedMessage.length + mac.length)
                .put(ed25519Id)
                .put(ntorOnionKey)
                .put(temporaryKeyPair.publicKey())
                .put(encryptedMessage)
                .put(mac)
                .array(), mac};
    }

    public static Keys finishNtorV3Handshake(byte[] ntorOnionKey, byte[] ed25519Id, KeyPair keyPair, byte[] relayPublicKey, byte[] MAC, byte[] auth, byte[] encryptedMessage) {
        return Cryptography.NTORv3_FINALKDF(keyPair.privateKey(), keyPair.publicKey(), ntorOnionKey, ed25519Id, relayPublicKey, MAC, auth, encryptedMessage);
    }

}
