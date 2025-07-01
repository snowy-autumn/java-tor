package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class TruncatedCommand extends RelayCell {

    // Truncated reasons are exactly the same as destroyed reasons. (That does not mean that all of them could be used for each)
    byte reason;

    public TruncatedCommand(int circuitId, byte reason) {
        super(circuitId, false, TRUNCATED, (short) 0);
        this.reason = reason;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }

    public byte getReason() {
        return reason;
    }
}
