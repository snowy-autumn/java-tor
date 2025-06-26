package snowy.autumn.tor.cell.cells.relay.commands;

import com.google.crypto.tink.hybrid.internal.X25519.KeyPair;
import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Handshakes;

import java.nio.ByteBuffer;

public class Extend2Command extends RelayCell {

    RouterMicrodesc routerMicrodesc;
    KeyPair temporaryKeyPair;

    public Extend2Command(int circuitId, RouterMicrodesc routerMicrodesc) {
        super(circuitId, true, EXTEND2, (short) 0);
        this.routerMicrodesc = routerMicrodesc;
        this.temporaryKeyPair = Cryptography.generateX25519KeyPair();
    }



    @Override
    protected byte[] serialiseRelayBody() {
        byte[] linkSpecifiers = routerMicrodesc.generateLinkSpecifiers();
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
