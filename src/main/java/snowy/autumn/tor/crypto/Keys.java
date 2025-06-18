package snowy.autumn.tor.crypto;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public record Keys(MessageDigest digestForward, MessageDigest digestBackward, Cipher encryptionKey, Cipher decryptionKey, byte[] KH) {

    public Keys(byte[] digestForward, byte[] digestBackward, byte[] encryptionKey, byte[] decryptionKey, byte[] KH) {
        this(
                Cryptography.createDigest("SHA-1", digestForward),
                Cryptography.createDigest("SHA-1", digestBackward),
                Cryptography.createAesKey(Cipher.ENCRYPT_MODE, encryptionKey),
                Cryptography.createAesKey(Cipher.DECRYPT_MODE, decryptionKey),
                KH);
    }

}
