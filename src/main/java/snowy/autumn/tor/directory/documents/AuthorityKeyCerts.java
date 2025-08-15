package snowy.autumn.tor.directory.documents;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import snowy.autumn.tor.crypto.Cryptography;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

public class AuthorityKeyCerts {

    public AuthorityKeyCerts() {

    }

    private static byte[] decodeFromString(String encoded) {
        String[] lines = encoded.trim().split("\n");
        return Base64.getDecoder().decode(String.join("", Arrays.copyOfRange(lines, 1, lines.length - 1)));
    }

    public static AuthorityKeyCerts parse(String document, byte[] fingerprint) {
        String[] documentParts = document.split("dir-key-certification\n");
        document = documentParts[0] + "dir-key-certification\n";
        documentParts[0] = document.substring(document.indexOf("dir-identity-key") + "dir-identity-key".length(), document.indexOf("-----END RSA PUBLIC KEY-----")) + "-----END RSA PUBLIC KEY-----";
        byte[] identityKey = decodeFromString(documentParts[0]);
        MessageDigest sha1 = Cryptography.createDigest("SHA-1");
        if (!Arrays.equals(sha1.digest(identityKey), fingerprint))
            throw new RuntimeException("The given fingerprint did not match the hashed authority identity key.");
        byte[] signature = decodeFromString(documentParts[1]);
        if (!verifySignature(identityKey, signature, sha1.digest(document.getBytes())))
            throw new RuntimeException("The signature is invalid for this authority key certificates document.");

        return new AuthorityKeyCerts();
    }

    public static boolean verifySignature(byte[] publicKey, byte[] signature, byte[] hash) {
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

}
