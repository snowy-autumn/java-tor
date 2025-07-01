package snowy.autumn.tor.hs;

import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.nio.ByteBuffer;

public record IntroductionPoint(byte[] linkSpecifiers, byte[] ntorOnionKey, byte[] authKey, byte[] encryptionKey) {

    public byte[] fingerprint() {
        // Parse the link specifiers
        ByteBuffer buffer = ByteBuffer.wrap(linkSpecifiers);
        byte linkSpecifierNum = buffer.get();

        for (int i = 0; i < linkSpecifierNum; i++) {
            byte linkSpecifierType = buffer.get();
            if (linkSpecifierType == RouterMicrodesc.LEGACY_ID_LINK_SPECIFIER) {
                byte linkSpecifierLength = buffer.get();
                if (linkSpecifierLength != 20) return null; // This should never happen as long as everything's on the other ends is done according to the spec.
                byte[] fingerprint = new byte[20];
                buffer.get(fingerprint);
                return fingerprint;
            }
        }

        return null;
    }

}
