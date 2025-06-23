package snowy.autumn.tor.crypto;

import com.google.crypto.tink.subtle.X25519;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Cryptography {

    public static byte SHA1_LENGTH = 20;
    public static byte SHA3_256_LENGTH = 32;
    public static byte KEY_LENGTH = 16;
    public static byte CIPHER_KEY_LENGTH = 32;
    public static byte MAC_KEY_LENGTH = 32;
    public static byte IV_LENGTH = 16;

    public static final String NTOR_PROTOID  = "ntor-curve25519-sha256-1";
    public static final String NTOR_t_mac    = NTOR_PROTOID + ":mac";
    public static final String NTOR_t_key    = NTOR_PROTOID + ":key_extract";
    public static final String NTOR_t_verify = NTOR_PROTOID + ":verify";

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

    private static byte[] sha256hmac(byte[] message, byte[] key) {
        Mac hmacSHA256 = null;
        try {
            hmacSHA256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
            hmacSHA256.init(secretKeySpec);
            return hmacSHA256.doFinal(message);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static Keys NTOR_KDF_RFC5869(byte[] x, byte[] X, byte[] ntorOnionKey, byte[] fingerprint, byte[] Y, byte[] auth) {
        try {
            byte[] sharedSecret = X25519.computeSharedSecret(x, Y);
            byte[] ntorSharedSecret = X25519.computeSharedSecret(x, ntorOnionKey);
            byte[] secretInput = ByteBuffer.allocate(sharedSecret.length + ntorSharedSecret.length + fingerprint.length + ntorOnionKey.length + X.length + Y.length + NTOR_PROTOID.length())
                    .put(sharedSecret)
                    .put(ntorSharedSecret)
                    .put(fingerprint)
                    .put(ntorOnionKey)
                    .put(X)
                    .put(Y)
                    .put(NTOR_PROTOID.getBytes())
                    .array();
            byte[] keySeed = sha256hmac(secretInput, NTOR_t_key.getBytes());
            byte[] verify = sha256hmac(secretInput, NTOR_t_verify.getBytes());

            byte[] authInput = ByteBuffer.allocate(verify.length + fingerprint.length + ntorOnionKey.length + Y.length + X.length + NTOR_PROTOID.length() + "Server".length())
                    .put(verify)
                    .put(fingerprint)
                    .put(ntorOnionKey)
                    .put(Y)
                    .put(X)
                    .put(NTOR_PROTOID.getBytes())
                    .put("Server".getBytes())
                    .array();

            authInput = sha256hmac(authInput, NTOR_t_mac.getBytes());

            if (!Arrays.equals(auth, authInput)) return null;

            byte[] prev = new byte[0];
            int totalSize = 92;
            ByteBuffer finalKey = ByteBuffer.allocate(totalSize);
            for (int keyNumber = 1; totalSize > 0; keyNumber++) {
                ByteBuffer temp = ByteBuffer.allocate(prev.length + NTOR_t_key.length() + 1);
                temp.put(prev);
                temp.put(NTOR_t_key.getBytes());
                temp.put((byte) keyNumber);
                prev = sha256hmac(keySeed, temp.array());
                int bytesDone = Math.min(totalSize, prev.length);
                totalSize -= bytesDone;
                finalKey.put(prev, 0, bytesDone);
            }
            byte[][] keys = new byte[][]{{SHA1_LENGTH}, {SHA1_LENGTH}, {KEY_LENGTH}, {KEY_LENGTH}, {SHA1_LENGTH}};
            finalKey.position(0);
            for (int i = 0; i < keys.length; i++) {
                keys[i] = new byte[keys[i][0]];
                finalKey.get(keys[i]);
            }

            return new Keys(keys[0], keys[1], keys[2], keys[3], keys[4]);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
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
