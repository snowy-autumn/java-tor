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
        // Flags. I will not implement them at the moment.
        buffer.putInt(0);

        return buffer.array();
    }
}
