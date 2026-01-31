package snowy.autumn.tor.circuit;

import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.hs.IntroductionPoint;

import java.util.Arrays;

public interface CanExtendTo {

    private static byte[] getFingerprint(CanExtendTo canExtendTo) {
        if (canExtendTo instanceof RouterMicrodesc routerMicrodesc) return routerMicrodesc.getFingerprint();
        else if (canExtendTo instanceof IntroductionPoint introductionPoint) return introductionPoint.fingerprint();
        else throw new RuntimeException("Encountered an instance of an unknown CanExtendTo type.");
    }

    private static byte[] getEd25519Id(CanExtendTo canExtendTo) {
        if (canExtendTo instanceof RouterMicrodesc routerMicrodesc) return routerMicrodesc.getFingerprint();
        else if (canExtendTo instanceof IntroductionPoint introductionPoint) return introductionPoint.fingerprint();
        else throw new RuntimeException("Encountered an instance of an unknown CanExtendTo type.");
    }

    static boolean equals(CanExtendTo a, CanExtendTo b) {
        if (a instanceof RouterMicrodesc aRM && b instanceof RouterMicrodesc bRM) return Arrays.equals(aRM.getMicrodescHash(), bRM.getMicrodescHash());
        return Arrays.equals(getFingerprint(a), getFingerprint(b)) && Arrays.equals(getEd25519Id(a), getEd25519Id(b));
    }

}
