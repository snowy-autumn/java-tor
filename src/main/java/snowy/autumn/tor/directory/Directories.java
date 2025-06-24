package snowy.autumn.tor.directory;

import com.google.crypto.tink.subtle.Hex;

public class Directories {

    public enum Authorities {
        MORIA1("moria1", "128.31.0.39", 9201, "1A25C6358DB91342AA51720A5038B72742732498"),
        TOR26("tor26", "217.196.147.77", 443, "FAA4BCA4A6AC0FB4CA2F8AD5A11D9E122BA894F6"),
        DIZUM("dizum", "45.66.35.11", 443, "7EA6EAD6FD83083C538F44038BBFA077587D"),
        GABELMOO("gabelmoo", "131.188.40.189", 443, "F2044413DAC2E02EE026B4735A19BCA1DE97281"),
        DANNEBENG("dannenberg", "193.23.244.244", 443, "7BE683E65D48141321C5ED92F075C55364AC"),
        MAATUSKA("maatuska", "171.25.193.9", 80, "BD6A829255CB08E66FBE7D3748363586E46B"),
        LONGCLAW("longclaw", "199.58.81.140", 443, "74A910646BCEEFBCD2E874FC1DC997430F968145"),
        BASTET("bastet", "204.13.164.118", 443, "24E2F139121D4394C54B5BC368B3B411857C413"),
        FARAVAHAR("faravahar", "216.218.219.41", 443, "E3E42D35F801C9D5AB23584E0025D56FE2B3");

        private final String name;
        private final String ipv4;
        private final int orport;
        private final byte[] fingerprint;

        Authorities(String name, String ipv4, int orport, String fingerprint) {
            this.name = name;
            this.ipv4 = ipv4;
            this.orport = orport;
            this.fingerprint = Hex.decode(fingerprint);
        }

        public String getIpv4() {
            return ipv4;
        }

        public int getORPort() {
            return orport;
        }

        public byte[] getFingerprint() {
            return fingerprint;
        }
    }

}
