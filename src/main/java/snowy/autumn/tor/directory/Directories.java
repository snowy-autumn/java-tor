package snowy.autumn.tor.directory;

public class Directories {

    public enum Authorities {
        MORIA1("moria1", "128.31.0.39", 9201),
        TOR26("tor26", "217.196.147.77", 443),
        DIZUM("dizum", "45.66.35.11", 443),
        GABELMOO("gabelmoo", "131.188.40.189", 443),
        DANNEBENG("dannenberg", "193.23.244.244", 443),
        MAATUSKA("maatuska", "171.25.193.9", 80),
        LONGCLAW("longclaw", "199.58.81.140", 443),
        BASTET("bastet", "204.13.164.118", 443),
        FARAVAHAR("faravahar", "216.218.219.41", 443);

        private final String name;
        private final String ipv4;
        private final int orport;

        Authorities(String name, String ipv4, int orport) {
            this.name = name;
            this.ipv4 = ipv4;
            this.orport = orport;
        }

        public String getIpv4() {
            return ipv4;
        }

        public int getORPort() {
            return orport;
        }
    }

}
