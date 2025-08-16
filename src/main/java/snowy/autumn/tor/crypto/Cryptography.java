package snowy.autumn.tor.crypto;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import snowy.autumn.tor.cell.cells.relay.commands.Introduce1Command;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.hs.IntroductionPoint;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import java.util.HexFormat;

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

    public static final String NTORv3_PROTOID = "ntor3-curve25519-sha3_256-1";
    public static final byte[] NTORv3_VER_ENCAP = ENCAP("circuit extend".getBytes());
    public static final byte[] NTORv3_t_msgkdf_ENCAP = ENCAP((NTORv3_PROTOID + ":kdf_phase1").getBytes());
    public static final byte[] NTORv3_t_msgmac_ENCAP = ENCAP((NTORv3_PROTOID + ":msg_mac").getBytes());
    public static final byte[] NTORv3_t_key_seed_ENCAP = ENCAP((NTORv3_PROTOID + ":key_seed").getBytes());
    public static final byte[] NTORv3_t_verify_ENCAP = ENCAP((NTORv3_PROTOID + ":verify").getBytes());
    public static final byte[] NTORv3_t_final_ENCAP = ENCAP((NTORv3_PROTOID + ":kdf_final").getBytes());
    public static final byte[] NTORv3_t_auth_ENCAP = ENCAP((NTORv3_PROTOID + ":auth_final").getBytes());

    public static final String HS_NTOR_PROTOID = "tor-hs-ntor-curve25519-sha3-256-1";
    // Yes, I know that all of these already have `hs` in their name.
    public static final String HS_NTOR_t_hsenc    = HS_NTOR_PROTOID + ":hs_key_extract";
    public static final String HS_NTOR_t_hsverify = HS_NTOR_PROTOID + ":hs_verify";
    public static final String HS_NTOR_t_hsmac    = HS_NTOR_PROTOID + ":hs_mac";
    public static final String HS_NTOR_m_hsexpand = HS_NTOR_PROTOID + ":hs_key_expand";

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

    public static boolean verifyRSASignature(byte[] publicKey, byte[] signature, byte[] hash) {
        RSAPublicKey rsaPublicKey = RSAPublicKey.getInstance(publicKey);
        BigInteger signatureInteger = new BigInteger(1, signature);
        byte[] decoded = signatureInteger.modPow(rsaPublicKey.getPublicExponent(), rsaPublicKey.getModulus()).toByteArray();
        String hex = HexFormat.of().formatHex(decoded);
        decoded = HexFormat.of().parseHex("0".repeat((hex.length() % 2 == 1) ? 3 : 2) + hex);
        int padding = decoded.length - 3 - hash.length;
        ByteBuffer buffer = ByteBuffer.allocate(2 + padding + 1 + hash.length);
        buffer.put(new byte[]{0, 1});
        byte[] paddingBytes = new byte[padding];
        Arrays.fill(paddingBytes, (byte) -1);
        buffer.put(paddingBytes);
        buffer.put((byte) 0);
        buffer.put(hash);

        return MessageDigest.isEqual(decoded, buffer.array());
    }

    public static byte[] ENCAP(byte[] data) {
        return ByteBuffer.allocate(8 + data.length).putLong(data.length).put(data).array();
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
        Mac hmacSHA256;
        try {
            hmacSHA256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
            hmacSHA256.init(secretKeySpec);
            return hmacSHA256.doFinal(message);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hsMac(byte[] macKey, byte[] salt, byte[] message) {
        // SHA3_256(INT_8(mac_key_len) | MAC_KEY | INT_8(salt_len) | SALT | ENCRYPTED)
        MessageDigest macDigest = createDigest("SHA3-256");
        macDigest.update(ByteBuffer.allocate(8).putLong(macKey.length).array());
        macDigest.update(macKey);
        if (salt != null) {
            macDigest.update(ByteBuffer.allocate(8).putLong(salt.length).array());
            macDigest.update(salt);
        }
        macDigest.update(message);
        return macDigest.digest();
    }

    public static byte[] hsMac(byte[] macKey, byte[] message) {
        // Note: The other hsMac function and this one might not be related, and I just don't remember the details exactly.
        // It doesn't matter though, as they operate very similarly, so I've simply modified the other one to make this work.
        return hsMac(macKey, null, message);
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

    public static Keys NTORv3_FINALKDF(byte[] x, byte[] X, byte[] B, byte[] ed25519Id, byte[] Y, byte[] MAC, byte[] auth, byte[] encryptedMessage) {
        byte[] Yx = computeSharedSecret(x, Y);

        byte[] Bx = computeSharedSecret(x, B);
        byte[] secretInput = ByteBuffer.allocate(Yx.length + Bx.length + ed25519Id.length + B.length + X.length + Y.length + NTORv3_PROTOID.length() + NTORv3_VER_ENCAP.length)
                .put(Yx)
                .put(Bx)
                .put(ed25519Id)
                .put(B)
                .put(X)
                .put(Y)
                .put(NTORv3_PROTOID.getBytes())
                .put(NTORv3_VER_ENCAP)
                .array();

        byte[] ntorKeySeed = createDigest("SHA3-256", NTORv3_t_key_seed_ENCAP).digest(secretInput);

        byte[] verify = createDigest("SHA3-256", NTORv3_t_verify_ENCAP).digest(secretInput);

        byte[] authInput = ByteBuffer.allocate(verify.length + ed25519Id.length + B.length + Y.length + X.length + MAC.length + ENCAP(encryptedMessage).length + NTORv3_PROTOID.length() + "Server".length())
                .put(verify)
                .put(ed25519Id)
                .put(B)
                .put(Y)
                .put(X)
                .put(MAC)
                .put(ENCAP(encryptedMessage))
                .put(NTORv3_PROTOID.getBytes())
                .put("Server".getBytes())
                .array();

        byte[] authExpected = createDigest("SHA3-256", NTORv3_t_auth_ENCAP).digest(authInput);
        if (!Arrays.equals(auth, authExpected)) return null;

        SHAKEDigest shakeDigest = new SHAKEDigest(256);
        shakeDigest.update(NTORv3_t_final_ENCAP, 0, NTORv3_t_final_ENCAP.length);
        shakeDigest.update(ntorKeySeed, 0, ntorKeySeed.length);

        byte[] encryptionKey = new byte[CIPHER_KEY_LENGTH];
        shakeDigest.doOutput(encryptionKey, 0, encryptionKey.length);
        byte[] serverMessage;
        try {
            serverMessage = createAesKey(Cipher.DECRYPT_MODE, encryptionKey).doFinal(encryptedMessage);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }

        byte[] clientDigest = new byte[SHA1_LENGTH];
        shakeDigest.doOutput(clientDigest, 0, clientDigest.length);
        byte[] serverDigest = new byte[SHA1_LENGTH];
        shakeDigest.doOutput(serverDigest, 0, serverDigest.length);
        byte[] clientKey = new byte[KEY_LENGTH];
        shakeDigest.doOutput(clientKey, 0, clientKey.length);
        byte[] serverKey = new byte[KEY_LENGTH];
        shakeDigest.doOutput(serverKey, 0, serverKey.length);

        // Here I'm using KH for storing serverMessage, since KH is not calculated as part of this handshake.
        return new Keys(clientDigest, serverDigest, clientKey, serverKey, serverMessage);
    }

    private static Keys HS_NTOR_KDF(byte[] keySeed) {
        // K = KDF(NTOR_KEY_SEED | m_hsexpand,    SHA3_256_LEN *2 + S_KEY_LEN* 2)
        SHAKEDigest shakeDigest = new SHAKEDigest(256);
        byte[] keyMaterial = ByteBuffer.allocate(keySeed.length + HS_NTOR_m_hsexpand.length())
                .put(keySeed)
                .put(HS_NTOR_m_hsexpand.getBytes())
                .array();

        shakeDigest.update(keyMaterial, 0, keyMaterial.length);

        byte[] digestForward = new byte[SHA3_256_LENGTH];
        byte[] digestBackward = new byte[SHA3_256_LENGTH];
        byte[] encryptForward = new byte[CIPHER_KEY_LENGTH];
        byte[] decryptBackward = new byte[CIPHER_KEY_LENGTH];
        shakeDigest.doOutput(digestForward, 0, digestForward.length);
        shakeDigest.doOutput(digestBackward, 0, digestBackward.length);
        shakeDigest.doOutput(encryptForward, 0, encryptForward.length);
        shakeDigest.doOutput(decryptBackward, 0, decryptBackward.length);

        return new Keys(digestForward, digestBackward, encryptForward, decryptBackward);
    }

    public static Keys deriveHsNtorKeys(byte[] x, byte[] X, IntroductionPoint introductionPoint, byte[] Y, byte[] auth) {
        byte[] B = introductionPoint.encryptionKey();
        byte[] xY = computeSharedSecret(x, Y);
        byte[] xB = computeSharedSecret(x, B);

        byte[] rendSecretHsInput = ByteBuffer.allocate(32 + 32 + 32 + 32 + 32 + 32 + HS_NTOR_PROTOID.length())
                .put(xY)
                .put(xB)
                .put(introductionPoint.authKey())
                .put(B)
                .put(X)
                .put(Y)
                .put(HS_NTOR_PROTOID.getBytes())
                .array();

        byte[] verify = Cryptography.hsMac(rendSecretHsInput, HS_NTOR_t_hsverify.getBytes());
        byte[] authInput = ByteBuffer.allocate(32 + 32 + 32 + 32 + 32 + HS_NTOR_PROTOID.length() + "Server".length())
                .put(verify)
                .put(introductionPoint.authKey())
                .put(B)
                .put(Y)
                .put(X)
                .put(HS_NTOR_PROTOID.getBytes())
                .put("Server".getBytes())
                .array();

        byte[] calculatedAuth = hsMac(authInput, HS_NTOR_t_hsmac.getBytes());
        if (!Arrays.equals(auth, calculatedAuth)) return null;

        byte[] NTOR_KEY_SEED = hsMac(rendSecretHsInput, HS_NTOR_t_hsenc.getBytes());

        return HS_NTOR_KDF(NTOR_KEY_SEED);
    }


    public static Introduce1Command.HsIntroKeys HS_INTRO_KDF(byte[] x, byte[] X, IntroductionPoint introductionPoint, HiddenService hiddenService) {
        SHAKEDigest shakeDigest = new SHAKEDigest(256);
        // intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
        shakeDigest.update(computeSharedSecret(x, introductionPoint.encryptionKey()), 0, 32);
        shakeDigest.update(introductionPoint.authKey(), 0, introductionPoint.authKey().length);
        shakeDigest.update(X, 0, X.length);
        shakeDigest.update(introductionPoint.encryptionKey(), 0, introductionPoint.encryptionKey().length);
        shakeDigest.update(HS_NTOR_PROTOID.getBytes(), 0, HS_NTOR_PROTOID.length());
        // t_hsenc
        shakeDigest.update(HS_NTOR_t_hsenc.getBytes(), 0, HS_NTOR_t_hsenc.length());
        // info
        shakeDigest.update(HS_NTOR_m_hsexpand.getBytes(), 0, HS_NTOR_m_hsexpand.length());
        shakeDigest.update(hiddenService.getOnionAddress().N_hs_subcredential(), 0, 32);
        // output keys (ENC_KEY, MAC_KEY)
        byte[] encryptionKey = new byte[CIPHER_KEY_LENGTH];
        byte[] macKey = new byte[MAC_KEY_LENGTH];

        shakeDigest.doOutput(encryptionKey, 0, encryptionKey.length);
        shakeDigest.doOutput(macKey, 0, macKey.length);

        return new Introduce1Command.HsIntroKeys(encryptionKey, macKey);
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
        byte[] aesKey = new byte[CIPHER_KEY_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] macKey = new byte[MAC_KEY_LENGTH];
        shakeDigest.doOutput(aesKey, 0, aesKey.length);
        shakeDigest.doOutput(iv, 0, iv.length);
        shakeDigest.doOutput(macKey, 0, macKey.length);

        byte[] calculatedMac = hsMac(macKey, salt, encrypted);

        if (!Arrays.equals(calculatedMac, mac)) return null;

        return Cryptography.createAesKey(Cipher.DECRYPT_MODE, aesKey, iv).update(encrypted);
    }

}
