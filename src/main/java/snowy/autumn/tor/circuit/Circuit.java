package snowy.autumn.tor.circuit;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.cell.cells.*;
import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.cell.cells.relay.commands.*;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.crypto.Keys;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;
import snowy.autumn.tor.relay.Handshakes;
import snowy.autumn.tor.relay.Relay;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

public class Circuit {

    int circuitId;
    ArrayList<Relay> relays = new ArrayList<>();
    ArrayList<Keys> relayKeys = new ArrayList<>();
    Guard guard;

    ArrayList<Cell> pendingCells = new ArrayList<>();
    HashSet<byte[]> lastDigests = new HashSet<>();
    ReentrantLock lastDigestsLock = new ReentrantLock();
    private final ReentrantLock pendingCellsLock = new ReentrantLock();
    HashMap<Short, Stream> streamDataHashMap = new HashMap<>();
    private final ReentrantLock streamsLock = new ReentrantLock();
    private static final byte NOT_SET = -2;
    private static final byte CONNECTED = -1;
    byte connected = NOT_SET;

    // quick access params
    int sendMeVersion = 0;

    public <T extends Collection<? extends Relay>> Circuit(int circuitId, T relays, Collection<? extends Keys> relayKeys) {
        this.circuitId = circuitId | 0x80000000;
        this.relays.addAll(relays);
        this.relayKeys.addAll(relayKeys);
        this.guard = (Guard) this.relays.getFirst();
        init();
    }

    public Circuit(int circuitId, Guard guard) {
        this.circuitId = circuitId | 0x80000000;
        relays.add(guard);
        this.guard = guard;
        init();
    }

    public void updateFromConsensus(MicrodescConsensus microdescConsensus) {
        sendMeVersion = microdescConsensus.sendMeEmitMinVersion();
    }

    private void init() {
        guard.addCircuit(circuitId, this);
    }

    public void addCell(Cell cell) {
        pendingCellsLock.lock();
        byte[] decryptedDigest = null;
        if (cell instanceof RelayCell.EncryptedRelayCell encryptedRelayCell) {
            byte[] encryptedBody = encryptedRelayCell.getEncryptedBody();
            for (Keys keys : relayKeys)
                encryptedBody = keys.decryptionKey().update(encryptedBody);
            decryptedDigest = new byte[4];
            System.arraycopy(encryptedBody, 5, decryptedDigest, 0, decryptedDigest.length);
            Arrays.fill(encryptedBody, 5, 9, (byte) 0);
            byte[] digest = Arrays.copyOf(Cryptography.updateDigest(relayKeys.getLast().digestBackward(), encryptedBody), 4);
            if (!Arrays.equals(digest, decryptedDigest)) throw new Error("Digests don't match on relay cell: " + Arrays.toString(digest) + " != " + Arrays.toString(decryptedDigest));
            cell = RelayCell.interpretCommand(circuitId, encryptedBody);
        }

        if (cell instanceof DataCommand dataCommand) {
            streamsLock.lock();
            Stream stream = streamDataHashMap.get(dataCommand.getStreamId());
            if (stream == null) throw new Error("Invalid stream id: " + dataCommand.getStreamId());
            stream.received(this, decryptedDigest);
            relays.getLast().received(this, decryptedDigest);
            streamsLock.unlock();
        }
        else if (cell instanceof EndCommand endCommand) {
            streamsLock.lock();
            streamDataHashMap.remove(endCommand.getStreamId());
            streamsLock.unlock();
        }
        else if (cell instanceof SendMeCommand sendMeCommand) {
            if (sendMeCommand.getSendMeVersion() == 1) {
                lastDigestsLock.lock();
                if (lastDigests.stream().noneMatch(digest -> Arrays.equals(digest, sendMeCommand.getDigest()))) {
                    // The spec isn't very specific about this, but I assume the circuit should be torn down if this ever happens.
                    System.out.println("VERY WRONG"); // this is here for debug purposes
                    destroy(false);
                }
                else lastDigests.clear();
                lastDigestsLock.unlock();
            }
            pendingCellsLock.unlock();
            return;
        }

        pendingCells.add(cell);
        pendingCellsLock.unlock();
    }

    public void handleSendMe(short streamId, byte[] digest) {
        sendCell(streamId == 0 ? new SendMeCommand(circuitId, streamId, sendMeVersion)
                : new SendMeCommand(circuitId, streamId, sendMeVersion, digest));
    }

    @SuppressWarnings("unchecked")
    private <T extends Cell> T getRelayCell(short streamId, Byte... relayCommand) {
        try {
            pendingCellsLock.lock();
            T found = (T) pendingCells.stream().filter(cell -> cell instanceof RelayCell relayCell &&
                    Arrays.stream(relayCommand).anyMatch(command -> command == relayCell.getRelayCommand()) &&
                    relayCell.getStreamId() == streamId).findFirst().orElse(null);
            if (found == null) return null;
            pendingCells.remove(found);
            return found;
        } finally {
            pendingCellsLock.unlock();
        }
    }

    public boolean isConnected() {
        return connected == CONNECTED;
    }

    public <T extends Cell> T waitForRelayCell(short streamId, Byte... relayCommand) {
        T cell = null;
        while (cell == null && (isConnected() || !pendingCells.isEmpty()))
            cell = getRelayCell(streamId, relayCommand);
        return cell;
    }

    @SuppressWarnings("unchecked")
    private <T extends Cell> T getCellByCommand(byte command) {
        try {
            pendingCellsLock.lock();
            T found = (T) pendingCells.stream().filter(cell -> cell.getCommand() == command).findFirst().orElse(null);
            if (found == null) return null;
            pendingCells.remove(found);
            return found;
        } finally {
            pendingCellsLock.unlock();
        }
    }

    private <T extends Cell> T waitForCellByCommand(byte command) {
        // Todo: Add timeout.
        T cell = null;
        while (cell == null)
            cell = getCellByCommand(command);
        return cell;
    }

    public boolean sendCell(Cell cell) {
        if (cell instanceof RelayCell relayCell) {
            byte[] body = relayCell.serialiseBody();
            // update the digest field
            byte[] digest = Cryptography.updateDigest(relayKeys.getLast().digestForward(), body);
            // Todo: Replace this part with an actual calculation of when the relay would send a SEND ME command and store only the right digest.
            lastDigestsLock.lock();
            lastDigests.add(digest);
            lastDigestsLock.unlock();
            System.arraycopy(digest, 0, body, 5, 4);
            // encrypt the relay cell body
            for (int i = relayKeys.size() - 1; i >= 0; i--) {
                body = relayKeys.get(i).encryptionKey().update(body);
            }
            return guard.sendCell(new RelayCell.EncryptedRelayCell(circuitId, relayCell.isEarly(), body));
        }
        else return guard.sendCell(cell);
    }

    public boolean createFast() {
        CreateFastCell createFastCell = new CreateFastCell(circuitId);
        guard.sendCell(createFastCell);
        CreatedFastCell createdFastCell = waitForCellByCommand(Cell.CREATED_FAST);
        Keys keys = Cryptography.kdfTor(createFastCell.getKeyMaterial(), createdFastCell.getKeyMaterial());
        relayKeys.add(keys);
        this.connected = CONNECTED;
        return createdFastCell.verify(keys) || Boolean.TRUE.equals(guard.terminate());
    }

    public boolean create2(RouterMicrodesc routerMicrodesc) {
        Create2Cell create2Cell = new Create2Cell(circuitId, routerMicrodesc);
        guard.sendCell(create2Cell);
        Created2Cell created2Cell = waitForCellByCommand(Cell.CREATED2);
        if (created2Cell == null) return false;
        Keys keys = Handshakes.finishNtorHandshake(routerMicrodesc.getNtorOnionKey(), routerMicrodesc.getFingerprint(), create2Cell.getKeyPair(), created2Cell.getPublicKey(), created2Cell.getAuth());
        relayKeys.add(keys);
        this.connected = CONNECTED;
        return keys != null || Boolean.TRUE.equals(guard.terminate());
    }

    public boolean extend2(RouterMicrodesc routerMicrodesc) {
        Extend2Command extend2Command = new Extend2Command(circuitId, routerMicrodesc);
        sendCell(extend2Command);
        Extended2Command extended2Command = waitForRelayCell((short) 0, RelayCell.EXTENDED2);
        if (extended2Command == null) return false;
        Keys keys = Handshakes.finishNtorHandshake(routerMicrodesc.getNtorOnionKey(), routerMicrodesc.getFingerprint(), extend2Command.getKeyPair(), extended2Command.getPublicKey(), extended2Command.getAuth());
        relayKeys.add(keys);
        return keys != null || Boolean.TRUE.equals(guard.terminate());
    }

    private void addStream(short streamId) {
        streamsLock.lock();
        streamDataHashMap.put(streamId, new Stream(streamId));
        streamsLock.unlock();
    }

    public boolean openStream(short streamId, String address, int port) {
        addStream(streamId);
        sendCell(new BeginCommand(circuitId, streamId, address, port));
        RelayCell relayCell = waitForRelayCell(streamId, RelayCell.CONNECTED, RelayCell.END);
        return relayCell instanceof ConnectedCommand;
    }

    public boolean openDirStream(short streamId) {
        addStream(streamId);
        sendCell(new BeginDirCommand(circuitId, streamId));
        RelayCell relayCell = waitForRelayCell(streamId, RelayCell.CONNECTED, RelayCell.END);
        return relayCell instanceof ConnectedCommand;
    }

    public boolean sendData(short streamId, byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        while (buffer.hasRemaining()) {
            byte[] next = new byte[Math.min(DataCommand.MAX_DATA_SIZE, buffer.remaining())];
            buffer.get(next);
            if (!sendCell(new DataCommand(circuitId, streamId, next))) return false;
        }
        return true;
    }

    public boolean destroy(boolean terminateGuard) {
        // Clients should always send NONE as the reason for a DESTROY cell.
        boolean success = sendCell(new DestroyCell(circuitId, connected = DestroyCell.DestroyReason.NONE.getReason()));
        guard.terminate();
        return success;
    }

    public void destroyed(byte reason) {
        connected = reason;
    }

    public byte getConnected() {
        return connected;
    }

    public int getCircuitId() {
        return circuitId;
    }
}
