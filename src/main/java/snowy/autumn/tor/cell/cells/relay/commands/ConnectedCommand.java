package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class ConnectedCommand extends RelayCell {

    public ConnectedCommand(int circuitId, short streamId) {
        super(circuitId, false, CONNECTED, streamId);
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }
}
