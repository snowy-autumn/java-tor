package snowy.autumn.tor.crypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Cryptography {

    public static byte SHA1_LENGTH = 20;
    public static byte SHA3_256_LENGTH = 32;
    public static byte KEY_LENGTH = 16;
    public static byte CIPHER_KEY_LENGTH = 32;
    public static byte MAC_KEY_LENGTH = 32;
    public static byte IV_LENGTH = 16;

    public static MessageDigest createDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static MessageDigest createDigest(String algorithm, byte[] init) {
        MessageDigest digest = createDigest(algorithm);
        digest.update(init);
        return digest;
    }

    public static MessageDigest cloneDigest(MessageDigest digest) {
        try {
            return (MessageDigest) digest.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] updateDigest(MessageDigest digest, byte[] data) {
        digest.update(data);
        return cloneDigest(digest).digest();
    }

    public static Keys kdfTor(byte[] X, byte[] Y) {
        MessageDigest sha1 = createDigest("SHA-1");

        int iterations = (int) Math.ceil((double) 92 / SHA1_LENGTH);
        ByteBuffer K = ByteBuffer.allocate(iterations * SHA1_LENGTH);
        byte[] K0 = ByteBuffer.allocate(41).put(X).put(Y).array();

        for (byte i = 0; i < iterations; i++) {
            K0[K0.length - 1] = i;
            K.put(sha1.digest(K0));
        }

        K.position(0);
        byte[][] keys = new byte[][]{{SHA1_LENGTH}, {SHA1_LENGTH}, {SHA1_LENGTH}, {KEY_LENGTH}, {KEY_LENGTH}};
        for (int i = 0; i < keys.length; i++) {
            keys[i] = new byte[keys[i][0]];
            K.get(keys[i]);
        }

        return new Keys(keys[1], keys[2], keys[3], keys[4], keys[0]);
    }

    public static Cipher createAesKey(int opmode, byte[] keyBytes) {
        try {
            Cipher key = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            key.init(opmode, keySpec, new IvParameterSpec(new byte[16]));
            return key;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

}
