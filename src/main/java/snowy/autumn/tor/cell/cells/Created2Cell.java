package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.relay.Handshakes;

public class Created2Cell extends Cell {

    byte[] relayPublicKey;
    byte[] auth;
    byte[] encryptedMessage;

    public Created2Cell(int circuitId, byte[] relayPublicKey, byte[] auth) {
        super(circuitId, CREATED2);
        this.relayPublicKey = relayPublicKey;
        this.auth = auth;
    }

    public Created2Cell(int circuitId, byte[] relayPublicKey, byte[] auth, byte[] encryptedMessage) {
        this(circuitId, relayPublicKey, auth);
        this.encryptedMessage = encryptedMessage;
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

    public short getHandshakeType() {
        return encryptedMessage == null ? Handshakes.NTOR : Handshakes.NTORv3;
    }

    public byte[] getEncryptedMessage() {
        return encryptedMessage;
    }

}
