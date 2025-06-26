package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

public class DestroyCell extends Cell {

    public enum DestroyReason {
        NONE("No reason given."),
        PROTOCOL("Tor protocol violation."),
        INTERNAL("Internal error."),
        REQUESTED("A client sent a TRUNCATE command."),
        HIBERNATING("Not currently operating; trying to save bandwidth."),
        RESOURCELIMIT("Out of memory, sockets, or circuit IDs."),
        CONNECTFAILED("Unable to reach relay."),
        OR_IDENTITY("Connected to relay, but its OR identity was not as expected."),
        CHANNEL_CLOSED("The OR connection that was carrying this circuit died."),
        FINISHED("The circuit has expired for being dirty or old."),
        TIMEOUT("Circuit construction took too long"),
        DESTROYED("The circuit was destroyed w/o client TRUNCATE"),
        NOSUCHSERVICE("Request for unknown hidden service");

        private final String explanation;

        DestroyReason(String reason) {
            this.explanation = reason;
        }

        public static DestroyReason get(int order) {
            return DestroyReason.values()[order];
        }

        public byte getReason() {
            return (byte) this.ordinal();
        }

        public String getExplanation() {
            return explanation;
        }
    }

    byte reason;

    public DestroyCell(int circuitId, DestroyReason reason) {
        super(circuitId, DESTROY);
        this.reason = reason.getReason();
    }

    public DestroyCell(int circuitId, byte reason) {
        super(circuitId, DESTROY);
        this.reason = reason;
    }

    public byte getReason() {
        return reason;
    }

    @Override
    protected byte[] serialiseBody() {
        return new byte[]{ reason };
    }
}
