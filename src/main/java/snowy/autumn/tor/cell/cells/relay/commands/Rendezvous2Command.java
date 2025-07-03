package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class Rendezvous2Command extends RelayCell {

    byte[] hsGeneratedPublicKey;
    byte[] auth;

    public Rendezvous2Command(int circuitId, byte[] hsGeneratedPublicKey, byte[] auth, byte[] rest) {
        super(circuitId, false, RENDEZVOUS2, (short) 0);
        this.hsGeneratedPublicKey = hsGeneratedPublicKey;
        this.auth = auth;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }

    public byte[] getPublicKey() {
        return hsGeneratedPublicKey;
    }

    public byte[] getAuth() {
        return auth;
    }
}
