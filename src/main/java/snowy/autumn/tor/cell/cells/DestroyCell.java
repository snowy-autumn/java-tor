package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

public class DestroyCell extends Cell {

    public static final byte NONE = 0;
    public static final byte PROTOCOL = 1;
    public static final byte INTERNAL = 2;
    public static final byte REQUESTED = 3;
    public static final byte HIBERNATING = 4;
    public static final byte RESOURCELIMIT = 5;
    public static final byte CONNECTFAILED = 6;
    public static final byte OR_IDENTITY = 7;
    public static final byte CHANNEL_CLOSED = 8;
    public static final byte FINISHED = 9;
    public static final byte TIMEOUT = 10;
    public static final byte DESTROYED = 11;
    public static final byte NOSUCHSERVICE = 12;

    byte reason;

    public DestroyCell(int circuitId, byte reason) {
        super(circuitId, DESTROY);
    }

    public byte getReason() {
        return reason;
    }

    @Override
    protected byte[] serialiseBody() {
        return new byte[]{ reason };
    }
}
