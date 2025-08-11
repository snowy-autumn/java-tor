package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

import java.nio.ByteBuffer;

public class BeginCommand extends RelayCell {

    byte[] addrport;

    public BeginCommand(int circuitId, short streamId, String address, int port) {
        super(circuitId, false, BEGIN, streamId);
        // To avoid fingerprinting, the address should be sent in lowercase, but I won't do that here (Just because it's simple to just pass them as lowercase ITFP).
        this.addrport = (address + ':' + port).getBytes();
    }

    @Override
    protected byte[] serialiseRelayBody() {
        ByteBuffer buffer = ByteBuffer.allocate(4 + addrport.length);
        // Addrport
        buffer.put(addrport);
        // Flags should be encoded here, and as the spec says ` Whenever 0 would be sent for FLAGS, FLAGS is omitted from the message body. `,
        // So since I don't support any flags at the moment, we can simply treat them as all zeroes and not send anything at all.

        return buffer.array();
    }
}
