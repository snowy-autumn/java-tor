package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

public class Created2Cell extends Cell {

    byte[] relayPublicKey;
    byte[] auth;

    public Created2Cell(int circuitId, byte[] relayPublicKey, byte[] auth) {
        super(circuitId, CREATED2);
        this.relayPublicKey = relayPublicKey;
        this.auth = auth;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }

    public byte[] getPublicKey() {
        return relayPublicKey;
    }

    public byte[] getAuth() {
        return auth;
    }
}
