package snowy.autumn.tor.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import snowy.autumn.tor.hs.HiddenService;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
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
    public static final String NTOR_m_expand = NTOR_PROTOID + ":key_expand";

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

    public static byte[] computeSharedSecret(byte[] privateKey, byte[] publicKey) {
        byte[] sharedSecret = new byte[32];
        new X25519PrivateKeyParameters(privateKey).generateSecret(new X25519PublicKeyParameters(publicKey), sharedSecret, 0);
        return sharedSecret;
    }

    public static Keys NTOR_KDF_RFC5869(byte[] x, byte[] X, byte[] ntorOnionKey, byte[] fingerprint, byte[] Y, byte[] auth) {
        byte[] sharedSecret = computeSharedSecret(x, Y);
        byte[] ntorSharedSecret = computeSharedSecret(x, ntorOnionKey);
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
            ByteBuffer temp = ByteBuffer.allocate(prev.length + NTOR_m_expand.length() + 1);
            temp.put(prev);
            temp.put(NTOR_m_expand.getBytes());
            temp.put((byte) keyNumber);
            prev = sha256hmac(temp.array(), keySeed);
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
    }

    public static Cipher createAesKey(int opmode, byte[] keyBytes, byte[] iv) {
        try {
            Cipher key = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            key.init(opmode, keySpec, new IvParameterSpec(iv));
            return key;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static Cipher createAesKey(int opmode, byte[] keyBytes) {
        return createAesKey(opmode, keyBytes, new byte[16]);
    }

    public static KeyPair generateX25519KeyPair() {

        X25519KeyPairGenerator keyPairGenerator = new X25519KeyPairGenerator();
        try {
            keyPairGenerator.init(new X25519KeyGenerationParameters(SecureRandom.getInstanceStrong()));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        return new KeyPair(((X25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate()).getEncoded(), ((X25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic()).getEncoded());
    }

    public static byte[] hsDescriptorDecrypt(HiddenService hiddenService, long revisionCounter, byte[] encryptedData, byte[] secretData, byte[] stringConstant) {
        ByteBuffer buffer = ByteBuffer.wrap(encryptedData);
        byte[] salt = new byte[16];
        byte[] encrypted = new byte[encryptedData.length - 48];
        byte[] mac = new byte[32];
        buffer.get(salt).get(encrypted).get(mac);

        SHAKEDigest shakeDigest = new SHAKEDigest(256);
        byte[] subcredential = hiddenService.getOnionAddress().N_hs_subcredential();

        // secretInput = secretData | subcredential | revisionCounter
        shakeDigest.update(secretData, 0, secretData.length);
        shakeDigest.update(subcredential, 0, subcredential.length);
        shakeDigest.update(ByteBuffer.allocate(8).putLong(revisionCounter).array(), 0, 8);
        // salt
        shakeDigest.update(salt, 0, salt.length);
        // string constant
        shakeDigest.update(stringConstant, 0, stringConstant.length);
        // keys = 32 bytes (AES), 16 bytes (IV), 32 bytes (MAC KEY)
        byte[] aesKey = new byte[32];
        byte[] iv = new byte[16];
        byte[] macKey = new byte[32];
        shakeDigest.doOutput(aesKey, 0, aesKey.length);
        shakeDigest.doOutput(iv, 0, iv.length);
        shakeDigest.doOutput(macKey, 0, macKey.length);

        // SHA3_256(INT_8(mac_key_len) | MAC_KEY | INT_8(salt_len) | SALT | ENCRYPTED)
        MessageDigest macDigest = createDigest("SHA3-256");
        macDigest.update(ByteBuffer.allocate(8).putLong(macKey.length).array());
        macDigest.update(macKey);
        macDigest.update(ByteBuffer.allocate(8).putLong(salt.length).array());
        macDigest.update(salt);
        macDigest.update(encrypted);

        if (!Arrays.equals(macDigest.digest(), mac)) return null;

        return Cryptography.createAesKey(Cipher.DECRYPT_MODE, aesKey, iv).update(encrypted);
    }

}
