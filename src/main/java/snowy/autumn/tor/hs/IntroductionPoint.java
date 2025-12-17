package snowy.autumn.tor.hs;

import snowy.autumn.tor.circuit.CanExtendTo;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.nio.ByteBuffer;

public record IntroductionPoint(byte[] linkSpecifiers, byte[] ntorOnionKey, byte[] authKey, byte[] encryptionKey, byte[] fingerprint, byte[] ed25519Id) implements CanExtendTo {

    public IntroductionPoint(byte[] linkSpecifiers, byte[] ntorOnionKey, byte[] authKey, byte[] encryptionKey) {
        this(linkSpecifiers, ntorOnionKey, authKey, encryptionKey, getSpecificFromLinkSpecifiers(linkSpecifiers, RouterMicrodesc.LEGACY_ID_LINK_SPECIFIER, 20), getSpecificFromLinkSpecifiers(linkSpecifiers, RouterMicrodesc.ED25519_ID_LINK_SPECIFIER, 32));
    }

    // NOTE: This method will be completely overhauled once java 25 becomes more mainstream and the flexible constructor bodies feature gets more widely supported.
    private static byte[] getSpecificFromLinkSpecifiers(byte[] linkSpecifiers, byte linkSpecifierType, int linkSpecifierLength) {
        // Parse the link specifiers
        ByteBuffer buffer = ByteBuffer.wrap(linkSpecifiers);
        byte linkSpecifierNum = buffer.get();

        byte[] linkSpecifier = new byte[linkSpecifierLength];

        for (int i = 0; i < linkSpecifierNum; i++) {
            byte lsType = buffer.get();
            byte lsLength = buffer.get();
            if (lsType == linkSpecifierType) {
                if (lsLength != linkSpecifierLength) throw new Error("Invalid link specifier provided: LS type " + linkSpecifierType + " with length " + lsLength); // This should never happen as long as everything's on the other ends is done according to the spec.
                buffer.get(linkSpecifier);
                return linkSpecifier;
            }
            else buffer.position(buffer.position() + lsLength);
        }

        return null;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CanExtendTo canExtendTo)) return false;
        return CanExtendTo.equals(canExtendTo, this);
    }

}
