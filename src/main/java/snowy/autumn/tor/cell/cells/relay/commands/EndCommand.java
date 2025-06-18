package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class EndCommand extends RelayCell {

    public final static byte REASON_MISC = 1;
    public final static byte REASON_RESOLVEFAILED = 2;
    public final static byte REASON_CONNECTREFUSED = 3;
    public final static byte REASON_EXITPOLICY = 4;
    public final static byte REASON_DESTROY = 5;
    public final static byte REASON_DONE = 6;
    public final static byte REASON_TIMEOUT = 7;
    public final static byte REASON_NOROUTE = 8;
    public final static byte REASON_HIBERNATING = 9;
    public final static byte REASON_INTERNAL = 10;
    public final static byte REASON_RESOURCELIMIT = 11;
    public final static byte REASON_CONNRESET = 12;
    public final static byte REASON_TORPROTOCOL = 13;
    public final static byte REASON_NOTDIRECTORY = 14;

    byte reason;

    public EndCommand(int circuitId, short streamId, byte reason) {
        super(circuitId, false, END, streamId);
        this.reason = reason;
    }

    public byte getReason() {
        return reason;
    }

    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[]{ reason };
    }
}
