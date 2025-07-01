package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.DestroyCell;
import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class TruncateCommand extends RelayCell {

    public TruncateCommand(int circuitId) {
        super(circuitId, false, TRUNCATE, (short) 0);
    }

    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[]{DestroyCell.DestroyReason.NONE.getReason() };
    }
}
