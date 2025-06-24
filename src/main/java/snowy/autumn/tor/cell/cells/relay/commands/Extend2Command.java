package snowy.autumn.tor.cell.cells.relay.commands;

import com.google.crypto.tink.subtle.X25519;
import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Handshakes;

import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.Arrays;
import com.google.crypto.tink.hybrid.internal.X25519.KeyPair;

public class Extend2Command extends RelayCell {

    public static final byte IPv4_LINK_SPECIFIER = 0;
    public static final byte IPv6_LINK_SPECIFIER = 1;
    public static final byte LEGACY_ID_LINK_SPECIFIER = 2;
    public static final byte ED25519_ID_LINK_SPECIFIER = 3;
    RouterMicrodesc routerMicrodesc;
    KeyPair temporaryKeyPair;

    public Extend2Command(int circuitId, RouterMicrodesc routerMicrodesc) {
        super(circuitId, true, EXTEND2, (short) 0);
        this.routerMicrodesc = routerMicrodesc;
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
    }

    public static byte[] ipv4linkSpecifier(String host, int port) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        // Link specifier type
        buffer.put(IPv4_LINK_SPECIFIER);
        // Link specifier data length
        buffer.put((byte) 6);
        // Link specifier data
        Arrays.stream(host.split("\\.")).mapToInt(Integer::parseInt).forEach(i -> buffer.put((byte) i));
        buffer.putShort((short) port);
        return buffer.array();
    }

    public static byte[] ipv6linkSpecifier(String host, int port) {
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

    public static byte[] legacyIdLinkSpecifier(byte[] fingerprint) {
        ByteBuffer buffer = ByteBuffer.allocate(2 + 20);
        // Link specifier type
        buffer.put(LEGACY_ID_LINK_SPECIFIER);
        // Link specifier data length
        buffer.put((byte) 20);
        // Link specifier data
        buffer.put(fingerprint);
        return buffer.array();
    }

    public static byte[] ed25519IdLinkSpecifier(byte[] ed25519Id) {
        ByteBuffer buffer = ByteBuffer.allocate(2 + 32);
        // Link specifier type
        buffer.put(ED25519_ID_LINK_SPECIFIER);
        // Link specifier data length
        buffer.put((byte) 32);
        // Link specifier data
        buffer.put(ed25519Id);
        return buffer.array();
    }

    public static byte[] generateLinkSpecifiers(RouterMicrodesc routerMicrodesc) {
        // LS order: IPv4, LegacyId, Ed25519Id, IPv6
        // We assume that the relay has at least three, which are: IPv4, LegacyId and Ed25519Id.
        boolean hasIpv6 = routerMicrodesc.hasIpv6Address();
        ByteBuffer buffer = ByteBuffer.allocate( 1 + 8 + 22 + 34 + (hasIpv6 ? 20 : 0));
        // Number of link specifiers
        buffer.put((byte) (3 + (hasIpv6 ? 1 : 0)));
        // IPv4 LS
        buffer.put(ipv4linkSpecifier(routerMicrodesc.getHost(), routerMicrodesc.getPort()));
        // Legacy Id LS
        buffer.put(legacyIdLinkSpecifier(routerMicrodesc.getFingerprint()));
        // ED25519 Id LS
        buffer.put(ed25519IdLinkSpecifier(routerMicrodesc.getEd25519Id()));
        // IPv6 LS
        if (hasIpv6) buffer.put(ipv6linkSpecifier(routerMicrodesc.getIpv6host(), routerMicrodesc.getIpv6port()));

        return buffer.array();
    }

    @Override
    protected byte[] serialiseRelayBody() {
        byte[] linkSpecifiers = generateLinkSpecifiers(routerMicrodesc);
        byte[] ntorBlock = Handshakes.generateNtorBlock(routerMicrodesc.getFingerprint(), routerMicrodesc.getNtorOnionKey(), temporaryKeyPair);
        ByteBuffer buffer = ByteBuffer.allocate(linkSpecifiers.length + 2 + 2 + ntorBlock.length);
        // Link specifiers
        buffer.put(linkSpecifiers);
        // Handshake type
        buffer.putShort(Handshakes.NTOR);
        // The length of the handshake data
        buffer.putShort((short) ntorBlock.length);
        // Handshake data
        buffer.put(ntorBlock);

        return buffer.array();
    }

    public KeyPair getKeyPair() {
        return temporaryKeyPair;
    }
}
