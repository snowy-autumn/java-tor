package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class BeginDirCommand extends RelayCell {

    public BeginDirCommand(int circuitId, short streamId) {
        super(circuitId, false, BEGIN_DIR, streamId);
    }

    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }
}
