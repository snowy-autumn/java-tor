package snowy.autumn.tor.cell.cells.relay;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.cell.cells.relay.commands.ConnectedCommand;
import snowy.autumn.tor.cell.cells.relay.commands.DataCommand;
import snowy.autumn.tor.cell.cells.relay.commands.EndCommand;
import snowy.autumn.tor.cell.cells.relay.commands.SendMeCommand;

import java.nio.ByteBuffer;
import java.util.Random;

public abstract class RelayCell extends Cell {

    public static class EncryptedRelayCell extends Cell {

        byte[] encryptedBody;

        public EncryptedRelayCell(int circuitId, byte[] encryptedBody) {
            super(circuitId, RELAY);
            this.encryptedBody = encryptedBody;
        }

        @Override
        protected byte[] serialiseBody() {
            return encryptedBody;
        }

        public byte[] getEncryptedBody() {
            return encryptedBody;
        }
    }

    public static final byte BEGIN = 1;
    public static final byte BEGIN_DIR = 13;
    public static final byte CONNECTED = 4;
    public static final byte END = 3;
    public static final byte DATA = 2;
    public static final byte SENDME = 5;
    public static final byte EXTEND2 = 14;
    public static final byte EXTENDED2 = 15;

    protected byte relayCommand;
    short streamId;

    public RelayCell(int circuitId, boolean early, byte relayCommand, short streamId) {
        super(circuitId, early ? RELAY_EARLY : RELAY);
        this.relayCommand = relayCommand;
        this.streamId = streamId;
    }

    protected abstract byte[] serialiseRelayBody();

    @Override
    public byte[] serialiseBody() {
        ByteBuffer buffer = ByteBuffer.allocate(FIXED_CELL_BODY_LENGTH);
        // Relay command	1 byte
        buffer.put(relayCommand);
        // ‘Recognized’	2 bytes
        buffer.putShort((short) 0);
        // StreamID	2 bytes
        buffer.putShort(streamId);
        // Digest	4 bytes
        buffer.putInt(0);
        // Length	2 bytes
        // Data	    Length bytes
        byte[] body = serialiseRelayBody();
        buffer.putShort((short) body.length);
        buffer.put(body);
        // Padding	CELL_BODY_LEN - 11 - Length bytes
        byte[] padding = new byte[buffer.remaining()];
        new Random().nextBytes(padding);
        buffer.put(padding);

        return buffer.array();
    }

    @SuppressWarnings("unchecked")
    public static <T extends RelayCell> T interpretCommand(int circuitId, byte[] body) {
        ByteBuffer buffer = ByteBuffer.wrap(body);
        byte command = buffer.get();
        // recognised (should be all zeros and since we don't need it anyway we can just skip past it)
        buffer.getShort();
        short streamId = buffer.getShort();
        // digest (should be all zeros and since we don't need it anyway we can just skip past it)
        buffer.getInt();
        // data length and data
        byte[] data = new byte[buffer.getShort()];
        buffer.get(data);
        // the rest is padding so we can just ignore it

        if (command == CONNECTED) {
            // Since we do not intend to cache the address given to us by the exit node, we can just skip parsing the relay command and return an empty cell.
            return (T) new ConnectedCommand(circuitId, streamId);
        }
        else if (command == DATA) {
            return (T) new DataCommand(circuitId, streamId, data);
        }
        else if (command == END) {
            return (T) new EndCommand(circuitId, streamId, data[0]);
        }
        else if (command == SENDME) {
            buffer = ByteBuffer.wrap(data);
            byte sendMeVersion = buffer.get();
            // Technically if the version is not recognised then the circuit should be torn down, but not very important right now.
            if (sendMeVersion == 0) return (T) new SendMeCommand(circuitId, streamId, sendMeVersion);
            byte[] digest = new byte[buffer.getShort()];
            buffer.get(digest);
            return (T) new SendMeCommand(circuitId, streamId, sendMeVersion, digest);
        }

        throw new Error("Unknown relay command received: " + command);
    }

    public byte getRelayCommand() {
        return relayCommand;
    }

    public short getStreamId() {
        return streamId;
    }
}
