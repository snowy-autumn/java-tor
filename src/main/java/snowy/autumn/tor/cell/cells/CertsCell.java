package snowy.autumn.tor.cell.cells;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.crypto.Certificate;
import snowy.autumn.tor.crypto.Cryptography;

import java.util.Arrays;

public class CertsCell extends Cell {

    Certificate[] certs;

    public CertsCell(Certificate[] certs) {
        super(0, CERTS);
        this.certs = certs;
    }

    public boolean verifyCertificates(byte[] tlsCertificate) {
        // If the responder is adhering to the protocol, then there should be exactly one IDENTITY_V_SIGNING_CERT and exactly one SIGNING_V_TLS_CERT.
        Certificate identityVSigningCert = Arrays.stream(certs).filter(cert -> cert.type() == Certificate.IDENTITY_V_SIGNING_CERT).findFirst().orElse(null);
        if (identityVSigningCert == null) return false;
        Certificate.Ed25519Cert certType4Ed25519 = Certificate.Ed25519Cert.parseEncodedCert(identityVSigningCert);

        Certificate.Ed25519Cert.Extension extension = Arrays.stream(certType4Ed25519.extensions())
                .filter(ext -> ext.type() == Certificate.Ed25519Cert.Extension.SIGNED_WITH_ED25519_KEY)
                .findFirst().orElse(null);
        if (extension == null) return false;


        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(extension.data());
        byte[] certType4EncodedSigned = certType4Ed25519.encodedSigned();
        if (!publicKey.verify(Ed25519.Algorithm.Ed25519, null, certType4EncodedSigned, 0, certType4EncodedSigned.length, certType4Ed25519.signature(), 0))
            return false;

        byte[] subjectKey = certType4Ed25519.certifiedKey();

        Certificate signingVTlsCert = Arrays.stream(certs).filter(cert -> cert.type() == Certificate.SIGNING_V_TLS_CERT).findFirst().orElse(null);
        if (signingVTlsCert == null) return false;
        Certificate.Ed25519Cert certType5Ed25519 = Certificate.Ed25519Cert.parseEncodedCert(signingVTlsCert);

        publicKey = new Ed25519PublicKeyParameters(subjectKey);
        byte[] certType5EncodedSigned = certType5Ed25519.encodedSigned();
        if (!publicKey.verify(Ed25519.Algorithm.Ed25519, null, certType5EncodedSigned, 0, certType5EncodedSigned.length, certType5Ed25519.signature(), 0))
            return false;

        byte[] digest = Cryptography.createDigest("SHA-256").digest(tlsCertificate);

        return Arrays.equals(digest, certType5Ed25519.certifiedKey());
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
