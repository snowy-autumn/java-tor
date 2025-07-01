package snowy.autumn.tor.crypto;

import java.nio.ByteBuffer;

public record Certificate(byte type, short length, byte[] encodedCert) {
    public static final byte IDENTITY_V_SIGNING_CERT = 4;
    public static final byte SIGNING_V_TLS_CERT = 5;
    public static final byte HS_IP_V_SIGNING = 9;

    public record Ed25519Cert(byte type, int expiration, byte certifiedKeyType, byte[] certifiedKey, Extension[] extensions, byte[] encodedSigned, byte[] signature) {

        public record Extension(byte type, byte flags, byte[] data) {
            public static final byte SIGNED_WITH_ED25519_KEY = 4;
        }

        public static Certificate.Ed25519Cert parseEncodedCert(Certificate cert) {
            ByteBuffer buffer = ByteBuffer.wrap(cert.encodedCert());
            // This is the version, which is always equal to 1 so we can discard it.
            buffer.get();
            // This is data that's actually relevant to the Tor Ed25519 Certificates.
            byte type = buffer.get();
            int expiration = buffer.getInt();
            byte certifiedKeyType = buffer.get();
            byte[] certifiedKey = new byte[32];
            buffer.get(certifiedKey);
            Certificate.Ed25519Cert.Extension[] extensions = new Certificate.Ed25519Cert.Extension[buffer.get()];
            for (int i = 0; i < extensions.length; i++) {
                byte[] extensionData = new byte[buffer.getShort()];
                byte extensionType = buffer.get();
                byte extensionFlags = buffer.get();
                buffer.get(extensionData);
                extensions[i] = new Certificate.Ed25519Cert.Extension(extensionType, extensionFlags, extensionData);
            }
            byte[] encodedSigned = new byte[cert.encodedCert().length - 64];
            System.arraycopy(cert.encodedCert(), 0, encodedSigned, 0, encodedSigned.length);

            byte[] signature = new byte[64];
            buffer.get(signature);

            return new Certificate.Ed25519Cert(type, expiration, certifiedKeyType, certifiedKey, extensions, encodedSigned, signature);
        }

    }
}
