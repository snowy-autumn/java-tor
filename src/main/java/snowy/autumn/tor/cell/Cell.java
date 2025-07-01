package snowy.autumn.tor.cell;

import snowy.autumn.tor.cell.cells.*;
import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.crypto.Certificate;

import java.nio.ByteBuffer;

public abstract class Cell {

    public @interface ClientDoesNotImplement {};

    public static final int FIXED_CELL_BODY_LENGTH = 509;

    public static final byte PADDING = 0;
    public static final byte VERSIONS = 7;
    public static final byte CERTS = (byte) 129;
    public static final byte AUTH_CHALLENGE = (byte) 130;
    public static final byte NET_INFO = 8;
    public static final byte CREATE_FAST = 5;
    public static final byte CREATED_FAST = 6;
    public static final byte CREATE2 = 10;
    public static final byte CREATED2 = 11;
    public static final byte RELAY = 3;
    public static final byte RELAY_EARLY = 9;
    public static final byte DESTROY = 4;

    int circuitId;
    byte command;

    public Cell(int circuitId, byte command) {
        this.circuitId = circuitId;
        this.command = command;
    }

    public static boolean isFixedLengthCell(byte command) {
        return Byte.toUnsignedInt(command) < 128 && Byte.toUnsignedInt(command) != VERSIONS;
    }

    public boolean isFixedLengthCell() {
        return isFixedLengthCell(command);
    }

    protected abstract byte[] serialiseBody();

    public byte[] serialiseCell() {
        byte[] body = serialiseBody();
        boolean fixedLengthCell = isFixedLengthCell();
        // When version < 4 then CIRCID_LEN == 2, but since we only support versions 4, 5 at the moment,
        // then the only time this happens is in the VERSIONS cell.
        int cellSize = 1 + (command == VERSIONS ? 2 : 4) + (fixedLengthCell ? FIXED_CELL_BODY_LENGTH : 2 + body.length);
        ByteBuffer buffer = ByteBuffer.allocate(cellSize);
        if (command == VERSIONS)
            buffer.putShort((short) circuitId);
        else
            buffer.putInt(circuitId);
        buffer.put(command);
        if (!fixedLengthCell)
            buffer.putShort((short) body.length);
        buffer.put(body);
        return buffer.array();
    }

    @SuppressWarnings("unchecked")
    public static <T extends Cell> T parseCell(int circuitId, byte command, byte[] body) {
        ByteBuffer buffer = ByteBuffer.wrap(body);
        switch (command) {
            case VERSIONS -> {
                int[] versions = new int[body.length / 2];
                for (int i = 0; i < versions.length; i++)
                    versions[i] = buffer.getShort();
                return (T) new VersionCell(versions);
            }
            case CERTS -> {
                Certificate[] certificates = new Certificate[buffer.get()];
                for (int i = 0; i < certificates.length; i++) {
                    byte certType = buffer.get();
                    short certLength = buffer.getShort();
                    byte[] encodedCert = new byte[certLength];
                    buffer.get(encodedCert);
                    certificates[i] = new Certificate(certType, certLength, encodedCert);
                }
                return (T) new CertsCell(certificates);
            }
            case AUTH_CHALLENGE -> {
                // Since clients don't care about auth_challenge cells, we can just skip parsing it.
                return (T) new AuthChallengeCell();
                // Since clients don't care about auth_challenge cells, we can just skip parsing it.
            }
            case NET_INFO -> {
                byte[] timestamp = new byte[4];
                buffer.get(timestamp);
                byte initiatorAddressType = buffer.get();
                byte initiatorAddressLength = buffer.get();
                byte[] initiatorAddress = new byte[initiatorAddressLength];
                buffer.get(initiatorAddress);

                NetInfoCell.Address[] senderAddresses = new NetInfoCell.Address[buffer.get()];
                for (int i = 0; i < senderAddresses.length; i++) {
                    byte addressType = buffer.get();
                    byte addressLength = buffer.get();
                    byte[] address = new byte[addressLength];
                    buffer.get(address);
                    senderAddresses[i] = new NetInfoCell.Address(addressType, address);
                }

                return (T) new NetInfoCell(timestamp, new NetInfoCell.Address(initiatorAddressType, initiatorAddress), senderAddresses);
            }
            case CREATED_FAST -> {
                byte[] keyMaterial = new byte[20];
                byte[] KH = new byte[20];
                buffer.get(keyMaterial);
                buffer.get(KH);
                return (T) new CreatedFastCell(circuitId, keyMaterial, KH);
            }
            case CREATED2 -> {
                // Todo: Add support for ntor-v3
                // Since we're only using the ntor handshake at the moment (NOT GOOD PRACTICE FOR MODERN CLIENTS),
                // we don't need to worry about parsing other handshake types.
                buffer.getShort(); // This should always be 64, so we can discard it.
                byte[] publicKey = new byte[32];
                buffer.get(publicKey);
                byte[] auth = new byte[32];
                buffer.get(auth);
                return (T) new Created2Cell(circuitId, publicKey, auth);
            }
            case RELAY -> {
                return (T) new RelayCell.EncryptedRelayCell(circuitId, false, body);
            }
            case DESTROY -> {
                return (T) new DestroyCell(circuitId, body[0]);
            }
            case PADDING -> {
                // For now, we'll just ignore padding cells.
                return null;
            }
            default -> throw new Error("Unknown cell received: " + command);
        }
    }

    public int getCircuitId() {
        return circuitId;
    }

    public byte getCommand() {
        return command;
    }

}
