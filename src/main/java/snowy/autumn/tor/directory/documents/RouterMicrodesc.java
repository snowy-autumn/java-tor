package snowy.autumn.tor.directory.documents;

import java.util.Base64;

public class RouterMicrodesc {

    String host;
    int port;
    byte[] fingerprint;
    String microdescHash;
    byte[] ntorOnionKey;

    public RouterMicrodesc(String host, int port, byte[] fingerprint, String microdescHash) {
        this.host = host;
        this.port = port;
        this.fingerprint = fingerprint;
        this.microdescHash = microdescHash;
    }

    public void updateFromMicrodesc(String microdesc) {
        int ntorOnionKeyStart = microdesc.indexOf("ntor-onion-key");
        ntorOnionKey = Base64.getDecoder().decode(microdesc.substring(ntorOnionKeyStart, microdesc.indexOf('\n', ntorOnionKeyStart)).split(" ")[1]);
    }

    public String getMicrodescHash() {
        return microdescHash;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public byte[] getFingerprint() {
        return fingerprint;
    }

    public byte[] getNtorOnionKey() {
        return ntorOnionKey;
    }
}
