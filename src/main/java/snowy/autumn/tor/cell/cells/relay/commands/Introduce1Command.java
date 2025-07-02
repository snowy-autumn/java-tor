package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.crypto.KeyPair;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.hs.IntroductionPoint;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;

public class Introduce1Command extends RelayCell {

    public record HsIntroKeys(Cipher encryptionKey, byte[] macKey) {

        public HsIntroKeys(byte[] encryptionKey, byte[] macKey) {
            this(
                    Cryptography.createAesKey(Cipher.ENCRYPT_MODE, encryptionKey),
                    macKey
            );
        }

    }

    RouterMicrodesc rendezvousPointMicrodesc;
    IntroductionPoint introductionPoint;
    byte[] rendezvousCookie;
    KeyPair temporaryKeyPair;
    HiddenService hiddenService;

    public Introduce1Command(int circuitId, IntroductionPoint introductionPoint, RouterMicrodesc rendezvousPointMicrodesc, byte[] rendezvousCookie, HiddenService hiddenService) {
        super(circuitId, false, INTRODUCE1, (short) 0);
        this.introductionPoint = introductionPoint;
        this.rendezvousPointMicrodesc = rendezvousPointMicrodesc;
        this.rendezvousCookie = rendezvousCookie;
        this.hiddenService = hiddenService;
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
    }

    private byte[] generateEncryptedPlaintext(int maxLength) {
        byte[] rendezvousLinkSpecifiers = rendezvousPointMicrodesc.generateLinkSpecifiers();
        ByteBuffer buffer = ByteBuffer.allocate(maxLength);
        buffer.put(rendezvousCookie);
        // Extensions
        buffer.put((byte) 0);
        // Rendezvous onion key type (only available one is 1 - ntor onion key)
        buffer.put((byte) 1);
        // Rendezvous onion key length - An ntor onion key is always 32 bytes long.
        buffer.putShort((byte) 32);
        // Rendezvous onion key
        buffer.put(rendezvousPointMicrodesc.getNtorOnionKey());
        // Rendezvous link specifiers
        buffer.put(rendezvousLinkSpecifiers);
        // Padding - filled with zeroes
        // The maximum size of the body is 490, since we should assume that proposal 340 will be implemented and thus reduce the maximum data possible in the cell.
        buffer.put(new byte[buffer.remaining()]);

        return buffer.array();
    }

    private byte[] generateEncrypted(Cipher encryptionKey, int maxLength) {
        byte[] encryptedPlaintext = generateEncryptedPlaintext(maxLength);
        byte[] encrypted = encryptionKey.update(encryptedPlaintext);
        ByteBuffer buffer = ByteBuffer.allocate(maxLength);
        buffer.put(encrypted);
        return buffer.array();
    }

    @Override
    protected byte[] serialiseRelayBody() {
        int MAX_LENGTH = 490;
        // Todo: Consider whether to not allow padding up to 490 bytes but rather up to 246, since we don't want the other end to know that we're not using an official tor implementation (i.e. ctor).
        ByteBuffer buffer = ByteBuffer.allocate(MAX_LENGTH - Cryptography.MAC_KEY_LENGTH);
        // Legacy key id. Note that this field should be all zeroes, since otherwise the introduction point will mistake this for the legacy version of introduce1.
        buffer.put(new byte[20]);
        // Auth key type (Only supported type at the moment is 2 - Ed25519 public key)
        buffer.put((byte) 2);
        // Auth key length
        buffer.putShort((short) introductionPoint.authKey().length);
        // Auth key
        buffer.put(introductionPoint.authKey());
        // Extensions (none)
        buffer.put((byte) 0);
        // Temporary public key
        buffer.put(temporaryKeyPair.publicKey());
        // Encrypted
        HsIntroKeys hsIntroKeys = Cryptography.HS_NTOR_KDF(temporaryKeyPair.privateKey(), temporaryKeyPair.publicKey(), introductionPoint, hiddenService);
        buffer.put(generateEncrypted(hsIntroKeys.encryptionKey(), buffer.remaining()));
        byte[] allFields = buffer.array();
        // Mac
        return ByteBuffer.allocate(MAX_LENGTH).put(allFields).put(Cryptography.hsMac(hsIntroKeys.macKey(), allFields)).array();
    }
}
