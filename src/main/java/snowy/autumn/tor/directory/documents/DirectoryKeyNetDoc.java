package snowy.autumn.tor.directory.documents;

import snowy.autumn.tor.crypto.Cryptography;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class DirectoryKeyNetDoc {

    byte[] directorySigningKey;
    byte[] fingerprint;

    public DirectoryKeyNetDoc(byte[] directorySigningKey, byte[] fingerprint) {
        this.directorySigningKey = directorySigningKey;
        this.fingerprint = fingerprint;
    }

    private static byte[] decodeFromString(String encoded) {
        String[] lines = encoded.trim().split("\n");
        return Base64.getDecoder().decode(String.join("", Arrays.copyOfRange(lines, 1, lines.length - 1)));
    }

    public static DirectoryKeyNetDoc parse(String document, byte[] fingerprint) {
        String[] documentParts = document.split("dir-key-certification\n");
        document = documentParts[0] + "dir-key-certification\n";
        documentParts[0] = document.substring(document.indexOf("dir-identity-key") + "dir-identity-key".length(), document.indexOf("-----END RSA PUBLIC KEY-----")) + "-----END RSA PUBLIC KEY-----";
        byte[] identityKey = decodeFromString(documentParts[0]);
        MessageDigest sha1 = Cryptography.createDigest("SHA-1");
        if (!Arrays.equals(sha1.digest(identityKey), fingerprint))
            throw new RuntimeException("The given fingerprint did not match the hashed directory identity key.");
        byte[] signature = decodeFromString(documentParts[1]);
        if (!Cryptography.verifyRSASignature(identityKey, signature, sha1.digest(document.getBytes())))
            throw new RuntimeException("The signature is invalid for this directory key certificates document.");

        byte[] directorySigningKey = decodeFromString(document.substring(
                document.indexOf("\n-----BEGIN RSA PUBLIC KEY-----", document.indexOf("\ndir-signing-key")) + 1,
                document.indexOf("\n-----END RSA PUBLIC KEY-----", document.indexOf("\ndir-signing-key")))
                + "\nend");

        return new DirectoryKeyNetDoc(directorySigningKey, fingerprint);
    }

    public boolean verifyRSASignature(byte[] signature, byte[] hash) {
        return Cryptography.verifyRSASignature(directorySigningKey, signature, hash);
    }

    public byte[] getFingerprint() {
        return fingerprint;
    }
}
