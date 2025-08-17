package snowy.autumn.tor.directory.documents;

import snowy.autumn.tor.crypto.Cryptography;

import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.TimeZone;

public class DirectoryKeyNetDoc {

    byte[] directorySigningKey;
    byte[] fingerprint;
    long published;
    long expires;

    public DirectoryKeyNetDoc(byte[] directorySigningKey, byte[] fingerprint, long published, long expires) {
        this.directorySigningKey = directorySigningKey;
        this.fingerprint = fingerprint;
        this.published = published;
        this.expires = expires;
    }

    private static byte[] decodeFromString(String encoded) {
        String[] lines = encoded.trim().split("\n");
        return Base64.getDecoder().decode(String.join("", Arrays.copyOfRange(lines, 1, lines.length - 1)));
    }

    private static long parseDate(String date) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            return simpleDateFormat.parse(date).toInstant().getEpochSecond();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
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

        int start = document.indexOf("dir-key-published ") + "dir-key-published ".length();
        long published = parseDate(document.substring(start, document.indexOf("\n", start)).trim());
        start = document.indexOf("dir-key-expires ") + "dir-key-expires ".length();
        long expires = parseDate(document.substring(start, document.indexOf("\n", start)).trim());

        return new DirectoryKeyNetDoc(directorySigningKey, fingerprint, published, expires);
    }

    public boolean verifyRSASignature(byte[] signature, byte[] hash) {
        return Cryptography.verifyRSASignature(directorySigningKey, signature, hash);
    }

    public byte[] getDirectorySigningKey() {
        return directorySigningKey;
    }

    public byte[] getFingerprint() {
        return fingerprint;
    }

    public long getPublished() {
        return published;
    }

    public long getExpires() {
        return expires;
    }

    public boolean isValid() {
        long now = Instant.now().getEpochSecond();
        return now >= published && now <= expires;
    }

}
