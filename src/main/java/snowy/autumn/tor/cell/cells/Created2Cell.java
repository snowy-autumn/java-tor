package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

public class Created2Cell extends Cell {

    byte[] serverPublicKey;
    byte[] auth;

    public Created2Cell(int circuitId, byte[] serverPublicKey, byte[] auth) {
        super(circuitId, CREATED2);
        this.serverPublicKey = serverPublicKey;
        this.auth = auth;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }

    public byte[] getPublicKey() {
        return serverPublicKey;
    }

    public byte[] getAuth() {
        return auth;
    }
}
