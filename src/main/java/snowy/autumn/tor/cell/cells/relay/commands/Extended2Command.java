package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class Extended2Command extends RelayCell {

    byte[] relayPublicKey;
    byte[] auth;

    public Extended2Command(int circuitId, byte[] relayPublicKey, byte[] auth) {
        super(circuitId, false, EXTENDED2, (short) 0);
        this.relayPublicKey = relayPublicKey;
        this.auth = auth;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }

    public byte[] getPublicKey() {
        return relayPublicKey;
    }

    public byte[] getAuth() {
        return auth;
    }
}
