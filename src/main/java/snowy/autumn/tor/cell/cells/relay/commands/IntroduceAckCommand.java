package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class IntroduceAckCommand extends RelayCell {

    public enum IntroduceAckStatus {
        SUCCESS("Success: message relayed to hidden service host."),
        UNRECOGNISED_SERVICE_ID("Failure: service ID not recognized"),
        BAD_MESSAGE_FORMAT("Bad message format"),
        CANT_RELAY_MESSAGE_TO_HS("Can't relay message to service");

        private final String explanation;

        IntroduceAckStatus(String reason) {
            this.explanation = reason;
        }

        public static IntroduceAckStatus get(int order) {
            return IntroduceAckStatus.values()[order];
        }

        public short getStatus() {
            return (short) this.ordinal();
        }

        public String getExplanation() {
            return explanation;
        }
    }

    IntroduceAckStatus status;

    public IntroduceAckCommand(int circuitId, IntroduceAckStatus status) {
        super(circuitId, false, INTRODUCE_ACK, (short) 0);
        this.status = status;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }

    public IntroduceAckStatus getStatus() {
        return status;
    }
}
