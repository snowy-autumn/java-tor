package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class BeginCommand extends RelayCell {

    public BeginCommand(int circuitId, short streamId) {
        super(circuitId, false, BEGIN, streamId);
    }

    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }
}
