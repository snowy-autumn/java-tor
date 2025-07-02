package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class RendezvousEstablishedCommand extends RelayCell {

    public RendezvousEstablishedCommand(int circuitId) {
        super(circuitId, false, RENDEZVOUS_ESTABLISHED, (short) 0);
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }
}
