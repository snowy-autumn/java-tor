package snowy.autumn.tor.hs;

import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.nio.ByteBuffer;

public record IntroductionPoint(byte[] linkSpecifiers, byte[] ntorOnionKey, byte[] authKey, byte[] encryptionKey, byte[] fingerprint) {

    public IntroductionPoint(byte[] linkSpecifiers, byte[] ntorOnionKey, byte[] authKey, byte[] encryptionKey) {
        this(linkSpecifiers, ntorOnionKey, authKey, encryptionKey, getFingerprintFromLinkSpecifiers(linkSpecifiers));
    }

    private static byte[] getFingerprintFromLinkSpecifiers(byte[] linkSpecifiers) {
        // Parse the link specifiers
        ByteBuffer buffer = ByteBuffer.wrap(linkSpecifiers);
        byte linkSpecifierNum = buffer.get();

        byte[] fingerprint = new byte[20];

        for (int i = 0; i < linkSpecifierNum; i++) {
            byte linkSpecifierType = buffer.get();
            byte linkSpecifierLength = buffer.get();
            if (linkSpecifierType == RouterMicrodesc.LEGACY_ID_LINK_SPECIFIER) {
                if (linkSpecifierLength != 20) throw new Error("Invalid link specifier provided: Fingerprint is of length " + linkSpecifierLength); // This should never happen as long as everything's on the other ends is done according to the spec.
                buffer.get(fingerprint);
                return fingerprint;
            }
            else buffer.position(buffer.position() + linkSpecifierLength);
        }

        return null;
    }

}
