package snowy.autumn.tor.hs;

import snowy.autumn.tor.circuit.Circuit;
import snowy.autumn.tor.directory.Directory;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.util.Base64;

public class HSDirectory extends Directory {

    public HSDirectory(MicrodescConsensus microdescConsensus, RouterMicrodesc directoryMicrodesc, Circuit circuit) {
        super(microdescConsensus, directoryMicrodesc, circuit);
    }

    public HiddenServiceDescriptor fetchHSDescriptor(HiddenService hiddenService) {
        String response = httpRequest("GET /tor/hs/3/" + Base64.getEncoder().encodeToString(hiddenService.getOnionAddress().blindedPublicKey()) + " HTTP/1.0\r\n\r\n");
        if (response == null) return null;
        if (!response.startsWith("HTTP/1.0 200 OK")) return null;

        String headers = response.substring(0, response.indexOf("\r\n\r\n"));
        String body = response.substring(response.indexOf("\r\n\r\n") + 4).replaceAll("\r\n", "\n");

        long revisionCounter = Long.parseLong(body.split("\nrevision-counter ")[1].split("\n")[0]);

        int beginSuperencrypted = body.indexOf("superencrypted\n-----BEGIN MESSAGE-----") + "superencrypted\n-----BEGIN MESSAGE-----".length();
        byte[] superencrypted = Base64.getDecoder().decode(body.substring(beginSuperencrypted , body.indexOf("-----END MESSAGE-----", beginSuperencrypted))
                .replaceAll("\n", ""));

        return new HiddenServiceDescriptor(hiddenService, revisionCounter, superencrypted);
    }

}
