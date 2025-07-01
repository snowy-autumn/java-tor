package snowy.autumn.tor.hs;

import snowy.autumn.tor.crypto.Certificate;
import snowy.autumn.tor.crypto.Cryptography;

import java.util.ArrayList;
import java.util.Base64;

public class HiddenServiceDescriptor {

    private ArrayList<IntroductionPoint> introductionPoints = new ArrayList<>();
    private boolean valid = false;

    public HiddenServiceDescriptor(HiddenService hiddenService, long revisionCounter, byte[] superencrypted) {
        // Note: Throughout the decryption process, I replace the bytes for '\r\n' with '\n'.
        // This is not required, but since it doesn't interfere with the decryption, I do it anyway.

        byte[] blindedPublicKey = hiddenService.getOnionAddress().blindedPublicKey();

        // First layer of encryption decryption.
        byte[] encryptedBytes = Cryptography.hsDescriptorDecrypt(hiddenService, revisionCounter, superencrypted, blindedPublicKey, "hsdir-superencrypted-data".getBytes());
        if (encryptedBytes == null) return;

        String encrypted = new String(encryptedBytes);
        encrypted = encrypted.substring(0, encrypted.indexOf("-----END MESSAGE-----") + "-----END MESSAGE-----".length()).replaceAll("\r\n", "\n");

        // Todo: Implement restricted discovery
        encrypted = encrypted.substring(encrypted.indexOf("encrypted\n-----BEGIN MESSAGE-----") + "encrypted\n-----BEGIN MESSAGE-----".length(), encrypted.indexOf("-----END MESSAGE-----"))
                .replaceAll("\n", "");
        byte[] decrypted = Cryptography.hsDescriptorDecrypt(hiddenService, revisionCounter, Base64.getDecoder().decode(encrypted), blindedPublicKey, "hsdir-encrypted-data".getBytes());

        if (decrypted == null) return;

        String descriptor = new String(decrypted).replaceAll("\r\n", "\n");

        int firstIntroductionPoint = descriptor.indexOf("\nintroduction-point");
        String params = descriptor.substring(0, firstIntroductionPoint);

        String[] introductionPoints = descriptor.substring(firstIntroductionPoint + "\nintroduction-point".length()).trim().split("introduction-point ");

        for (String introductionPoint : introductionPoints) {
            byte[] linkSpecifiers = Base64.getDecoder().decode(introductionPoint.split("\n")[0]);
            // Todo: Crosscheck the link-specifiers from the microdesc-consensus and microdescs fetched from the directory.
            byte[] ntorOnionKey = Base64.getDecoder().decode(introductionPoint.split("onion-key ntor ")[1].split("\n")[0]);
            int beginAuthKey = introductionPoint.indexOf("\nauth-key\n");
            byte[] authKeyCertBytes = Base64.getDecoder().decode(
                    introductionPoint.substring(beginAuthKey + "\nauth-key\n-----BEGIN ED25519 CERT-----\n".length(), introductionPoint.indexOf("-----END ED25519 CERT-----", beginAuthKey))
                            .replaceAll("\n", "")
            );
            Certificate.Ed25519Cert authKeyCert = Certificate.Ed25519Cert.parseEncodedCert(new Certificate(Certificate.HS_IP_V_SIGNING, (short) authKeyCertBytes.length, authKeyCertBytes));
            byte[] authKey = authKeyCert.certifiedKey();
            byte[] encryptionKey = Base64.getDecoder().decode(introductionPoint.split("enc-key ntor ")[1].split("\n")[0]);

            this.introductionPoints.add(new IntroductionPoint(linkSpecifiers, ntorOnionKey, authKey, encryptionKey));;
        }

        valid = true;
    }

    public boolean isValid() {
        return valid;
    }
}
