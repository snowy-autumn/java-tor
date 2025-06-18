package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

import java.nio.ByteBuffer;

public class NetInfoCell extends Cell {

    public static record Address(byte addressType, byte[] address) {}

    byte[] timestamp;
    Address peerAddress;
    Address[] addresses;

    public NetInfoCell(byte[] timestamp, Address peerAddress, Address[] addresses) {
        super(0, NET_INFO);
        this.timestamp = timestamp;
        this.peerAddress = peerAddress;
        this.addresses = addresses;
    }

    @Override
    protected byte[] serialiseBody() {
        int addressesLength = 0;
        for (Address address : addresses) addressesLength += address.address().length;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 1 + 1 + peerAddress.address().length + 1 + addressesLength);

        buffer.put(timestamp);
        buffer.put(peerAddress.addressType());
        buffer.put((byte) peerAddress.address().length);
        buffer.put(peerAddress.address());

        buffer.put((byte) addresses.length);
        for (Address address : addresses) {
            buffer.put(address.addressType());
            buffer.put((byte) address.address().length);
            buffer.put(address.address());
        }

        return buffer.array();
    }

    public Address[] getAddresses() {
        return addresses;
    }

}
