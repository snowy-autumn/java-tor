package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class EndCommand extends RelayCell {

    public enum EndReason {
        REASON_MISC("catch-all for unlisted reasons"),
        REASON_RESOLVEFAILED("couldn't look up hostname"),
        REASON_CONNECTREFUSED("remote host refused connection"),
        REASON_EXITPOLICY("Relay refuses to connect to host or port"),
        REASON_DESTROY("Circuit is being destroyed"),
        REASON_DONE("Anonymized TCP connection was closed"),
        REASON_TIMEOUT("Connection timed out, or relay timed out while connecting"),
        REASON_NOROUTE("Routing error while attempting to contact destination"),
        REASON_HIBERNATING("Relay is temporarily hibernating"),
        REASON_INTERNAL("Internal error at the relay"),
        REASON_RESOURCELIMIT("Relay has no resources to fulfill request"),
        REASON_CONNRESET("Connection was unexpectedly reset"),
        REASON_TORPROTOCOL("Sent when closing connection because of Tor protocol violations."),
        REASON_NOTDIRECTORY("Client sent RELAY_BEGIN_DIR to a non-directory relay");

        private final String explanation;

        EndReason(String reason) {
            this.explanation = reason;
        }

        public static EndReason get(int order) {
            return values()[order - 1];
        }

        public byte getReason() {
            return (byte) (this.ordinal() + 1);
        }

        public String getExplanation() {
            return explanation;
        }
    }

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
