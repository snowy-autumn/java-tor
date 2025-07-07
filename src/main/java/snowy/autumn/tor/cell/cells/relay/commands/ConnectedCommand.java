package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

public class ConnectedCommand extends RelayCell {

    public static final byte NONE = 0;
    public static final byte INVALID = -1;
    public static final byte IPV4 = 4;
    public static final byte IPV6 = 6;

    byte addressType;
    byte[] hostAddress;

    public ConnectedCommand(int circuitId, short streamId, byte addressType, byte[] hostAddress) {
        super(circuitId, false, CONNECTED, streamId);
        this.addressType = addressType;
        this.hostAddress = hostAddress;
    }

    public ConnectedCommand(int circuitId, short streamId) {
        this(circuitId, streamId, NONE, null);
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseRelayBody() {
        return new byte[0];
    }

    public boolean isInvalid() {
        return addressType == INVALID;
    }

    public boolean hasAddress() {
        return addressType != NONE && addressType != INVALID;
    }

    public byte getAddressType() {
        return addressType;
    }

    public byte[] getHostAddress() {
        return hostAddress;
    }
}
