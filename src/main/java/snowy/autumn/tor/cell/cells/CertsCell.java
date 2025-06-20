package snowy.autumn.tor.cell.cells;

import com.google.crypto.tink.signature.Ed25519PublicKey;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.InvalidProtocolBufferException;
import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.crypto.Cryptography;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class CertsCell extends Cell {

    public record Cert(byte type, short length, byte[] encodedCert) {
        public static final byte IDENTITY_V_SIGNING_CERT = 4;
        public static final byte SIGNING_V_TLS_CERT = 5;
    }

    public record Ed25519Cert(byte type, int expiration, byte certifiedKeyType, byte[] certifiedKey, Extension[] extensions, byte[] encodedSigned, byte[] signature) {

        public record Extension(byte type, byte flags, byte[] data) {
            public static final byte SIGNED_WITH_ED25519_KEY = 4;
        }

    }

    Cert[] certs;

    public CertsCell(Cert[] certs) {
        super(0, CERTS);
        this.certs = certs;
    }

    private Ed25519Cert parseEncodedCert(Cert cert) {
        ByteBuffer buffer = ByteBuffer.wrap(cert.encodedCert());
        // This is the version, which is always equal to 1 so we can discard it.
        buffer.get();
        // This is data that's actually relevant to the Tor Ed25519 Certificate.
        byte type = buffer.get();
        int expiration = buffer.getInt();
        byte certifiedKeyType = buffer.get();
        byte[] certifiedKey = new byte[32];
        buffer.get(certifiedKey);
        Ed25519Cert.Extension[] extensions = new Ed25519Cert.Extension[buffer.get()];
        for (int i = 0; i < extensions.length; i++) {
            byte[] extensionData = new byte[buffer.getShort()];
            byte extensionType = buffer.get();
            byte extensionFlags = buffer.get();
            buffer.get(extensionData);
            extensions[i] = new Ed25519Cert.Extension(extensionType, extensionFlags, extensionData);
        }
        byte[] encodedSigned = new byte[cert.encodedCert().length - 64];
        System.arraycopy(cert.encodedCert(), 0, encodedSigned, 0, encodedSigned.length);

        byte[] signature = new byte[64];
        buffer.get(signature);

        return new Ed25519Cert(type, expiration, certifiedKeyType, certifiedKey, extensions, encodedSigned, signature);
    }

    public boolean verifyCertificates(byte[] tlsCertificate) {
        // If the responder is adhering to the protocol, then there should be exactly one IDENTITY_V_SIGNING_CERT and exactly one SIGNING_V_TLS_CERT.
        Cert identityVSigningCert = Arrays.stream(certs).filter(cert -> cert.type() == Cert.IDENTITY_V_SIGNING_CERT).findFirst().orElse(null);
        if (identityVSigningCert == null) return false;
        Ed25519Cert certType4Ed25519 = parseEncodedCert(identityVSigningCert);

        try {
            Ed25519Cert.Extension extension = Arrays.stream(certType4Ed25519.extensions())
                    .filter(ext -> ext.type() == Ed25519Cert.Extension.SIGNED_WITH_ED25519_KEY)
                    .findFirst().orElse(null);
            if (extension == null) return false;

            Ed25519PublicKey publicKey = Ed25519PublicKey.create(Bytes.copyFrom(extension.data()));
            Ed25519Verify.create(publicKey).verify(certType4Ed25519.signature(), certType4Ed25519.encodedSigned());

            byte[] subjectKey = certType4Ed25519.certifiedKey();

            Cert signingVTlsCert = Arrays.stream(certs).filter(cert -> cert.type() == Cert.SIGNING_V_TLS_CERT).findFirst().orElse(null);
            if (signingVTlsCert == null) return false;
            Ed25519Cert certType5Ed25519 = parseEncodedCert(signingVTlsCert);

            publicKey = Ed25519PublicKey.create(Bytes.copyFrom(subjectKey));
            Ed25519Verify.create(publicKey).verify(certType5Ed25519.signature(), certType5Ed25519.encodedSigned());
            byte[] digest = Cryptography.createDigest("SHA-256").digest(tlsCertificate);

            return Arrays.equals(digest, certType5Ed25519.certifiedKey());
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
