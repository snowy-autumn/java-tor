package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class DataCommand extends RelayCell {

    public static final short MAX_DATA_SIZE = Cell.FIXED_CELL_BODY_LENGTH - 11;

    byte[] data;

    public DataCommand(int circuitId, short streamId, byte[] data) {
        super(circuitId, false, DATA, streamId);
        this.data = data;
    }

    public byte[] getData() {
        return data;
    }

    @Override
    protected byte[] serialiseRelayBody() {
        return data;
    }
}
