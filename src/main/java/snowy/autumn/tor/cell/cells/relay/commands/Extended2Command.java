package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.relay.Handshakes;

public class Extended2Command extends RelayCell {

    byte[] relayPublicKey;
    byte[] auth;
    byte[] encryptedMessage;

    public Extended2Command(int circuitId, byte[] relayPublicKey, byte[] auth) {
        super(circuitId, false, EXTENDED2, (short) 0);
        this.relayPublicKey = relayPublicKey;
        this.auth = auth;
    }

    public Extended2Command(int circuitId, byte[] relayPublicKey, byte[] auth, byte[] encryptedMessage) {
        this(circuitId, relayPublicKey, auth);
        this.encryptedMessage = encryptedMessage;
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

    public short getHandshakeType() {
        return encryptedMessage == null ? Handshakes.NTOR : Handshakes.NTORv3;
    }

    public byte[] getEncryptedMessage() {
        return encryptedMessage;
    }
}
