package snowy.autumn.tor.directory.documents;

import java.util.Base64;

public class RouterMicrodesc {

    String host;
    int port;
    byte[] fingerprint;
    String microdescHash;
    byte[] ntorOnionKey;
    byte[] ed25519Id;

    String ipv6host;
    int ipv6port;

    public RouterMicrodesc(String host, int port, byte[] fingerprint, String microdescHash, String ipv6host, int ipv6port) {
        // We assume that every relay in the consensus has at least an ipv4 address, fingerprint and an ed25519 identity.
        this.host = host;
        this.port = port;
        this.fingerprint = fingerprint;
        this.microdescHash = microdescHash;
        this.ipv6host = ipv6host;
        this.ipv6port = ipv6port;
    }

    public void updateFromMicrodesc(String microdesc) {
        int ntorOnionKeyStart = microdesc.indexOf("ntor-onion-key");
        ntorOnionKey = Base64.getDecoder().decode(microdesc.substring(ntorOnionKeyStart, microdesc.indexOf('\n', ntorOnionKeyStart)).split(" ")[1]);

        int ed25519IdStart = microdesc.indexOf("id ed25519");
        int ed25519IdStop = microdesc.indexOf('\n', ed25519IdStart);
        String ed25519Substring = ed25519IdStop == -1 ? microdesc.substring(ed25519IdStart) : microdesc.substring(ed25519IdStart, ed25519IdStop);
        ed25519Id = Base64.getDecoder().decode(ed25519Substring.split(" ")[2]);
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

    public byte[] getEd25519Id() {
        return ed25519Id;
    }

    public String getIpv6host() {
        return ipv6host;
    }

    public int getIpv6port() {
        return ipv6port;
    }

    public boolean hasIpv6Address() {
        return ipv6host != null;
    }

}
