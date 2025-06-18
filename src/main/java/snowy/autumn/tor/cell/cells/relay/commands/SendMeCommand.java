package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class SendMeCommand extends RelayCell {

    int sendMeVersion;

    public SendMeCommand(int circuitId, short streamId, int sendMeVersion) {
        super(circuitId, false, SENDME, streamId);
        this.sendMeVersion = sendMeVersion;
    }

    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }
}
