package snowy.autumn.tor.cell.cells.relay;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.cell.cells.relay.commands.*;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public abstract class RelayCell extends Cell {

    public static class EncryptedRelayCell extends Cell {

        byte[] encryptedBody;

        public EncryptedRelayCell(int circuitId, boolean early, byte[] encryptedBody) {
            super(circuitId, early ? RELAY_EARLY : RELAY);
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
    public static final byte TRUNCATE = 8;
    public static final byte TRUNCATED = 9;
    public static final byte INTRODUCE1 = 34;
    public static final byte INTRODUCE_ACK = 40;
    public static final byte ESTABLISH_RENDEZVOUS = 33;
    public static final byte RENDEZVOUS_ESTABLISHED = 39;
    public static final byte RENDEZVOUS2 = 37;

    protected byte relayCommand;
    short streamId;
    boolean early;

    public RelayCell(int circuitId, boolean early, byte relayCommand, short streamId) {
        super(circuitId, early ? RELAY_EARLY : RELAY);
        this.early = early;
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
        // recognised (should be all zeroes and since we don't need it anyway we can just skip past it)
        buffer.getShort();
        short streamId = buffer.getShort();
        // digest (should be all zeroes and since we don't need it anyway we can just skip past it)
        buffer.getInt();
        // data length and data
        byte[] data = new byte[buffer.getShort()];
        buffer.get(data);
        // the rest is padding so we can just ignore it

        switch (command) {
            case CONNECTED -> {
                if (data.length == 0)
                    return (T) new ConnectedCommand(circuitId, streamId);

                buffer = ByteBuffer.wrap(data);
                byte addressType = data.length == 8 ? ConnectedCommand.IPV4 : ConnectedCommand.IPV6;
                byte[] address = new byte[addressType == ConnectedCommand.IPV4 ? 4 : 16];
                buffer.get(address);
                if (data.length > 8) {
                    // This should only happen when the returned address is an IPv6 address.
                    byte receivedType = buffer.get();
                    if (receivedType != addressType || !Arrays.equals(Arrays.copyOf(address, 4), new byte[4]))
                        return (T) new ConnectedCommand(circuitId, streamId, ConnectedCommand.INVALID, null);
                    buffer.get(address);
                }

                return (T) new ConnectedCommand(circuitId, streamId, addressType, address);
            }
            case DATA -> {
                return (T) new DataCommand(circuitId, streamId, data);
            }
            case END -> {
                return (T) new EndCommand(circuitId, streamId, data[0]);
            }
            case SENDME -> {
                buffer = ByteBuffer.wrap(data);
                // The spec only mentions this vaguely once, but I figured it might help prevent a few crashes.
                if (buffer.remaining() == 0) return (T) new SendMeCommand(circuitId, streamId, 0, null);

                byte sendMeVersion = buffer.get();
                // Technically if the version is not recognised then the circuit should be torn down, but not very important right now.
                if (sendMeVersion == 0) return (T) new SendMeCommand(circuitId, streamId, sendMeVersion);
                byte[] digest = new byte[buffer.getShort()];
                buffer.get(digest);
                return (T) new SendMeCommand(circuitId, streamId, sendMeVersion, digest);
            }
            case EXTENDED2 -> {
                buffer = ByteBuffer.wrap(data);
                short handshakeSize = buffer.getShort();
                byte[] publicKey = new byte[32];
                buffer.get(publicKey);
                byte[] auth = new byte[32];
                buffer.get(auth);
                if (handshakeSize == 64)
                    // ntor handshake
                    return (T) new Extended2Command(circuitId, publicKey, auth);
                else if (handshakeSize > 64) {
                    // ntor-v3 handshake
                    byte[] encryptedMessage = new byte[handshakeSize - 64];
                    buffer.get(encryptedMessage);
                    return (T) new Extended2Command(circuitId, publicKey, auth, encryptedMessage);
                }
                else
                    throw new Error("Unknown handshake size: " + handshakeSize);
            }
            case TRUNCATED -> {
                return (T) new TruncatedCommand(circuitId, data[0]);
            }
            case INTRODUCE_ACK -> {
                // Todo: Figure out if there are any existing extensions for INTRODUCE_ACK. Since unrecognised extensions are ignored anyway, it shouldn't pose a problem.
                return (T) new IntroduceAckCommand(circuitId, IntroduceAckCommand.IntroduceAckStatus.get(ByteBuffer.wrap(data).getShort()));
            }
            case RENDEZVOUS_ESTABLISHED -> {
                return (T) new RendezvousEstablishedCommand(circuitId);
            }
            case RENDEZVOUS2 -> {
                byte[] publicKey = new byte[32];
                byte[] auth = new byte[32];
                ByteBuffer.wrap(data).get(publicKey).get(auth);
                return (T) new Rendezvous2Command(circuitId, publicKey, auth, data);
            }
            default -> throw new Error("Unknown relay command received: " + command);
        }
    }

    public byte getRelayCommand() {
        return relayCommand;
    }

    public short getStreamId() {
        return streamId;
    }

    public boolean isEarly() {
        return early;
    }
}
