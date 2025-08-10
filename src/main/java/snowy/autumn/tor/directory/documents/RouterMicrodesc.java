package snowy.autumn.tor.directory.documents;

import org.bouncycastle.util.encoders.Hex;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

public class RouterMicrodesc {

    public static class Flags {
        public static final byte GUARD = 1;
        public static final byte EXIT = (1 << 1);
        public static final byte BAD_EXIT = (1 << 2);
        public static final byte FAST = (1 << 3);
        public static final byte HS_DIR = (1 << 4);
        public static final byte MIDDLE_ONLY = (1 << 5);
    }

    public static final byte IPv4_LINK_SPECIFIER = 0;
    public static final byte IPv6_LINK_SPECIFIER = 1;
    public static final byte LEGACY_ID_LINK_SPECIFIER = 2;
    public static final byte ED25519_ID_LINK_SPECIFIER = 3;

    String host;
    int port;
    byte[] fingerprint;
    String microdescHash;
    byte[] ntorOnionKey;
    byte[] ed25519Id;
    byte[][] family = new byte[0][20];

    String ipv6host;
    int ipv6port;
    // Only some flags will be stored in this value.
    // 1bit - Guard, 2bit - Exit, 3bit - BadExit, 4bit - Fast, 5bit - HSDir, 6bit - MiddleOnly
    byte flags = 0;

    public RouterMicrodesc(String host, int port, byte[] fingerprint, String microdescHash, String ipv6host, int ipv6port, String[] flags) {
        // We assume that every relay in the consensus has at least an ipv4 address, fingerprint and an ed25519 identity.
        this.host = host;
        this.port = port;
        this.fingerprint = fingerprint;
        this.microdescHash = microdescHash;
        this.ipv6host = ipv6host;
        this.ipv6port = ipv6port;
        setFlags(flags);
    }

	public RouterMicrodesc(byte flags, byte[] host, short port, byte[] fingerprint, byte[] ed25519Id, byte[] ntorOnionKey, byte[] microdescHash, byte[] ipv6host, short ipv6port, byte[][] family) {
		this.flags = flags;
		try {
			this.host = Inet4Address.getByAddress(host).getHostAddress();
		}
		catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
		this.port = Short.toUnsignedInt(port);
		this.fingerprint = fingerprint;
		this.ed25519Id = ed25519Id;
		this.ntorOnionKey = ntorOnionKey;
		this.microdescHash = Base64.getEncoder().withoutPadding().encodeToString(microdescHash);
		try {
			this.ipv6host = ipv6host == null ? null : Inet6Address.getByAddress(ipv6host).getHostAddress();
		}
		catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
		this.ipv6port = Short.toUnsignedInt(ipv6port);
        this.family = family;
	}

    private void setFlags(String[] flags) {
        for (String flag : flags) {
            switch (flag) {
                case "guard" -> this.flags |= Flags.GUARD;
                case "exit" -> this.flags |= Flags.EXIT;
                case "badexit" -> this.flags |= Flags.BAD_EXIT;
                case "fast" -> this.flags |= Flags.FAST;
                case "hsdir" -> this.flags |= Flags.HS_DIR;
                case "middleonly" -> this.flags |= Flags.MIDDLE_ONLY;
            }
        }
    }

    public boolean isFlag(byte flag) {
        return (flags & flag) != 0;
    }

	public byte getFlags() {
		return flags;
	}

    public void updateFromMicrodesc(String microdesc) {
        int ntorOnionKeyStart = microdesc.indexOf("ntor-onion-key");
        ntorOnionKey = Base64.getDecoder().decode(microdesc.substring(ntorOnionKeyStart, microdesc.indexOf('\n', ntorOnionKeyStart)).split(" ")[1]);

        int ed25519IdStart = microdesc.indexOf("id ed25519");
        int ed25519IdStop = microdesc.indexOf('\n', ed25519IdStart);
        String ed25519Substring = ed25519IdStop == -1 ? microdesc.substring(ed25519IdStart) : microdesc.substring(ed25519IdStart, ed25519IdStop);
        ed25519Id = Base64.getDecoder().decode(ed25519Substring.split(" ")[2]);

        int familyStart = microdesc.indexOf("family ");
        if (familyStart != -1) {
            int familyStop = microdesc.indexOf('\n', familyStart);
            String[] familyList = (familyStop == -1 ? microdesc.substring(familyStart + "family ".length()) : microdesc.substring(familyStart + "family ".length(), familyStop)).split(" ");
            // Usually we'd want to include router nicknames that are listed, as part of the family, but for now we won't handle this case.
            // This shouldn't be that big of a problem, since the majority of family entries are rsa identities.
            familyList = Arrays.stream(familyList).filter(router -> router.startsWith("$")).toList().toArray(new String[0]);
            family = new byte[familyList.length][20];

            for (int i = 0; i < familyList.length; i++) {
                family[i] = Hex.decode(familyList[i].substring(1));
            }
        }

    }

    public static byte[] ipv4linkSpecifier(String host, int port) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        // Link specifier type
        buffer.put(IPv4_LINK_SPECIFIER);
        // Link specifier data length
        buffer.put((byte) 6);
        // Link specifier data
        Arrays.stream(host.split("\\.")).forEachOrdered(i -> buffer.put((byte) Integer.parseInt(i)));
        buffer.putShort((short) port);
        return buffer.array();
    }

    public byte[] ipv6linkSpecifier(String host, int port) {
        try {
            ByteBuffer buffer = ByteBuffer.allocate(20);
            // Link specifier type
            buffer.put(IPv6_LINK_SPECIFIER);
            // Link specifier data length
            buffer.put((byte) 18);
            // Link specifier data
            buffer.put(Inet6Address.getByName(host).getAddress());
            buffer.putShort((short) port);
            return buffer.array();
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] legacyIdLinkSpecifier(byte[] fingerprint) {
        ByteBuffer buffer = ByteBuffer.allocate(2 + 20);
        // Link specifier type
        buffer.put(LEGACY_ID_LINK_SPECIFIER);
        // Link specifier data length
        buffer.put((byte) 20);
        // Link specifier data
        buffer.put(fingerprint);
        return buffer.array();
    }

    public byte[] ed25519IdLinkSpecifier(byte[] ed25519Id) {
        ByteBuffer buffer = ByteBuffer.allocate(2 + 32);
        // Link specifier type
        buffer.put(ED25519_ID_LINK_SPECIFIER);
        // Link specifier data length
        buffer.put((byte) 32);
        // Link specifier data
        buffer.put(ed25519Id);
        return buffer.array();
    }

    public byte[] generateLinkSpecifiers() {
        // LS order: IPv4, LegacyId, Ed25519Id, IPv6
        // We assume that the relay has at least three, which are: IPv4, LegacyId and Ed25519Id.
        boolean hasIpv6 = hasIpv6Address();
        ByteBuffer buffer = ByteBuffer.allocate( 1 + 8 + 22 + 34 + (hasIpv6 ? 20 : 0));
        // Number of link specifiers
        buffer.put((byte) (3 + (hasIpv6 ? 1 : 0)));
        // IPv4 LS
        buffer.put(ipv4linkSpecifier(host, port));
        // Legacy Id LS
        buffer.put(legacyIdLinkSpecifier(fingerprint));
        // ED25519 Id LS
        buffer.put(ed25519IdLinkSpecifier(ed25519Id));
        // IPv6 LS
        if (hasIpv6) buffer.put(ipv6linkSpecifier(ipv6host, ipv6port));

        return buffer.array();
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

    public byte[][] getFamily() {
        return family;
    }
}
