package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class EstablishRendezvousCommand extends RelayCell {

    byte[] rendezvousCookie = new byte[20];

    public EstablishRendezvousCommand(int circuitId) {
        super(circuitId, false, ESTABLISH_RENDEZVOUS, (short) 0);
        try {
            SecureRandom.getInstanceStrong().nextBytes(rendezvousCookie);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected byte[] serialiseRelayBody() {
        return rendezvousCookie;
    }

    public byte[] getRendezvousCookie() {
        return rendezvousCookie;
    }
}
