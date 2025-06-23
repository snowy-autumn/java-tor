package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class Extend2Command extends RelayCell {

    public Extend2Command(int circuitId, short streamId) {
        super(circuitId, true, EXTEND2, streamId);
    }

    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }
}
