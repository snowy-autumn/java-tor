package snowy.autumn.tor.circuit;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.cell.cells.*;
import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.cell.cells.relay.commands.*;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.crypto.KeyPair;
import snowy.autumn.tor.crypto.Keys;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.hs.IntroductionPoint;
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

    private final ReentrantLock truncateLock = new ReentrantLock();

    // quick access params
    int sendMeVersion = 0;

    public <T extends Collection<? extends Relay>> Circuit(int circuitId, T relays, Collection<? extends Keys> relayKeys) {
        this.circuitId = getValidCircuitId(circuitId);
        for (Relay relay : relays)
            addRelay(relay);
        this.relayKeys.addAll(relayKeys);
        this.guard = (Guard) this.relays.getFirst();
        init();
    }

    public Circuit(int circuitId, Guard guard) {
        this.circuitId = getValidCircuitId(circuitId);
        this.guard = addRelay(guard);
        init();
    }

    public static int getValidCircuitId(int circuitId) {
        return circuitId | 0x80000000;
    }

    public void updateFromConsensus(MicrodescConsensus microdescConsensus) {
        sendMeVersion = microdescConsensus.getSendMeMinVersion();
    }

    private void init() {
        guard.addCircuit(circuitId, this);
    }

    private <T extends Relay> T addRelay(T relay) {
        relay.initialiseDeliverWindow(circuitId);
        this.relays.add(relay);
        return relay;
    }

    public void addCell(Cell cell) {
        truncateLock.lock();
        pendingCellsLock.lock();
        byte[] relayCellDigest = null;
        if (cell instanceof RelayCell.EncryptedRelayCell encryptedRelayCell) {
            byte[] encryptedBody = encryptedRelayCell.getEncryptedBody();
            for (Keys keys : relayKeys)
                encryptedBody = keys.decryptionKey().update(encryptedBody);
            relayCellDigest = new byte[4];
            System.arraycopy(encryptedBody, 5, relayCellDigest, 0, relayCellDigest.length);
            Arrays.fill(encryptedBody, 5, 9, (byte) 0);
            byte[] digest = Arrays.copyOf(Cryptography.updateDigest(relayKeys.getLast().digestBackward(), encryptedBody), 20);
            if (!Arrays.equals(digest, 0, 4, relayCellDigest, 0, 4)) throw new Error("Digests don't match on relay cell: " + Arrays.toString(digest) + " != " + Arrays.toString(relayCellDigest));
            relayCellDigest = digest;
            cell = RelayCell.interpretCommand(circuitId, encryptedBody);
        }

        if (cell instanceof DataCommand dataCommand) {
            streamsLock.lock();
            Stream stream = streamDataHashMap.get(dataCommand.getStreamId());
            if (stream == null) throw new Error("Invalid stream id: " + dataCommand.getStreamId());
            stream.received(this, relayCellDigest);
            relays.getLast().received(this, relayCellDigest);
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
        truncateLock.unlock();
    }

    public void handleSendMe(short streamId, byte[] digest) {
        sendCell(streamId != 0 ? new SendMeCommand(circuitId, streamId, sendMeVersion)
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
        while (cell == null && (guard.isConnected() && (isConnected() || connected == NOT_SET || !pendingCells.isEmpty())))
            cell = getCellByCommand(command);
        return cell;
    }

    public boolean sendRelayCell(RelayCell relayCell, int level) {
        byte[] body = relayCell.serialiseBody();
        // update the digest field
        byte[] digest = Cryptography.updateDigest(relayKeys.get(level).digestForward(), body);
        // Todo: Replace this part with an actual calculation of when the relay would send a SEND ME command and store only the right digest.
        lastDigestsLock.lock();
        lastDigests.add(Arrays.copyOf(digest, 20));
        lastDigestsLock.unlock();
        System.arraycopy(digest, 0, body, 5, 4);
        // encrypt the relay cell body
        for (int i = level; i >= 0; i--) {
            body = relayKeys.get(i).encryptionKey().update(body);
        }
        return guard.sendCell(new RelayCell.EncryptedRelayCell(circuitId, relayCell.isEarly(), body));
    }

    public boolean sendRelayCell(RelayCell relayCell) {
        return sendRelayCell(relayCell, relayKeys.size() - 1);
    }

    public boolean sendCell(Cell cell) {
        if (cell instanceof RelayCell relayCell) return sendRelayCell(relayCell);
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

    public boolean create2(RouterMicrodesc routerMicrodesc, short handshakeType) {
        Create2Cell create2Cell = new Create2Cell(circuitId, routerMicrodesc, handshakeType);
        guard.sendCell(create2Cell);
        Created2Cell created2Cell = waitForCellByCommand(Cell.CREATED2);
        if (created2Cell == null) return false;
        Keys keys = null;
        if (created2Cell.getHandshakeType() == Handshakes.NTOR)
            keys = Handshakes.finishNtorHandshake(routerMicrodesc.getNtorOnionKey(), routerMicrodesc.getFingerprint(), create2Cell.getKeyPair(), created2Cell.getPublicKey(), created2Cell.getAuth());
        else if (created2Cell.getHandshakeType() == Handshakes.NTORv3) {
            keys = Handshakes.finishNtorV3Handshake(routerMicrodesc.getNtorOnionKey(), routerMicrodesc.getEd25519Id(), create2Cell.getKeyPair(), created2Cell.getPublicKey(), create2Cell.getMac(), created2Cell.getAuth(), created2Cell.getEncryptedMessage());
            byte[] serverMessage = keys.KH();
            // There are no supported ntor-v3 extensions at the moment, so serverMessage is currently not being used.
        }
        relayKeys.add(keys);
        this.connected = CONNECTED;
        return keys != null || Boolean.TRUE.equals(guard.terminate());
    }

    /**
     I intend to hopefully replace this Relay(introduction_point, 0) with an actual Relay of the introduction point, after I finish the modifications specified in
     IntroductionPoint#getSpecificFromLinkSpecifiers(byte[], byte, int)
     **/
    @SuppressWarnings("ConstantConditions")
    public boolean extend2(IntroductionPoint introductionPoint) {
        Extend2Command extend2Command = new Extend2Command(circuitId, introductionPoint);
        boolean result = extend2(extend2Command, introductionPoint.ntorOnionKey(), introductionPoint.fingerprint(), introductionPoint.ed25519Id());
        return result && addRelay(new Relay("introduction_point", 0)) != null;
    }

    public boolean extend2(RouterMicrodesc routerMicrodesc) {
        return extend2(routerMicrodesc, routerMicrodesc.getEd25519Id() == null ? Handshakes.NTOR : Handshakes.NTORv3);
    }

    @SuppressWarnings("ConstantConditions")
    public boolean extend2(RouterMicrodesc routerMicrodesc, short handshakeType) {
        Extend2Command extend2Command = new Extend2Command(circuitId, routerMicrodesc, handshakeType);
        boolean result = extend2(extend2Command, routerMicrodesc.getNtorOnionKey(), routerMicrodesc.getFingerprint(), routerMicrodesc.getEd25519Id());
        return result && addRelay(new Relay(routerMicrodesc.getHost(), routerMicrodesc.getPort())) != null;
    }

    public boolean extend2(CanExtendTo extendableObject) {
        if (extendableObject instanceof RouterMicrodesc routerMicrodesc) return extend2(routerMicrodesc, routerMicrodesc.getEd25519Id() == null ? Handshakes.NTOR : Handshakes.NTORv3);
        else if (extendableObject instanceof IntroductionPoint introductionPoint) return extend2(introductionPoint);
        else throw new RuntimeException("Got an unknown type of CanExtendTo instance.");
    }

    public boolean extend2(CanExtendTo extendableObject, short handshakeType) {
        if (extendableObject instanceof RouterMicrodesc routerMicrodesc) return extend2(routerMicrodesc, handshakeType);
        else if (extendableObject instanceof IntroductionPoint introductionPoint) return extend2(introductionPoint, handshakeType);
        else throw new RuntimeException("Got an unknown type of CanExtendTo instance.");
    }

    private boolean extend2(Extend2Command extend2Command, byte[] ntorOnionKey, byte[] fingerprint, byte[] ed25519Id) {
        sendCell(extend2Command);
        Extended2Command extended2Command = waitForRelayCell((short) 0, RelayCell.EXTENDED2);
        if (extended2Command == null) return false;
        Keys keys = null;
        if (extended2Command.getHandshakeType() == Handshakes.NTOR)
            keys = Handshakes.finishNtorHandshake(ntorOnionKey, fingerprint, extend2Command.getKeyPair(), extended2Command.getPublicKey(), extended2Command.getAuth());
        else if (extended2Command.getHandshakeType() == Handshakes.NTORv3) {
            keys = Handshakes.finishNtorV3Handshake(ntorOnionKey, ed25519Id, extend2Command.getKeyPair(), extended2Command.getPublicKey(), extend2Command.getMac(), extended2Command.getAuth(), extended2Command.getEncryptedMessage());
            byte[] serverMessage = keys.KH();
            // There are no supported ntor-v3 extensions at the moment, so serverMessage is currently not being used.
        }
        relayKeys.add(keys);
        return keys != null || Boolean.TRUE.equals(guard.terminate());
    }

    public byte[] establishRendezvous() {
        EstablishRendezvousCommand establishRendezvousCommand = new EstablishRendezvousCommand(circuitId);
        if (!sendCell(establishRendezvousCommand)) return null;
        RendezvousEstablishedCommand rendezvousEstablished = waitForRelayCell((short) 0, RelayCell.RENDEZVOUS_ESTABLISHED);
        return rendezvousEstablished != null ? establishRendezvousCommand.getRendezvousCookie() : null;
    }

    public IntroduceAckCommand.IntroduceAckStatus introduce1(IntroductionPoint introductionPoint, RouterMicrodesc rendezvousPoint, byte[] rendezvousCookie, HiddenService hiddenService) {
        Introduce1Command introduce1 = new Introduce1Command(circuitId, introductionPoint, rendezvousPoint, rendezvousCookie, hiddenService);
        if (!sendCell(introduce1)) return null;
        IntroduceAckCommand introduceAck = waitForRelayCell((short) 0, RelayCell.INTRODUCE_ACK);
        introduceAck.getStatus().setKeyPair(introduce1.getKeyPair());
        return introduceAck.getStatus();
    }

    public boolean rendezvous(KeyPair keyPair, IntroductionPoint introductionPoint) {
        Rendezvous2Command rendezvous2 = waitForRelayCell((short) 0, RelayCell.RENDEZVOUS2);
        Keys keys = Cryptography.deriveHsNtorKeys(keyPair.privateKey(), keyPair.publicKey(), introductionPoint, rendezvous2.getPublicKey(), rendezvous2.getAuth());
        if (keys != null) relayKeys.add(keys);
        return keys != null;
    }

    private void addStream(short streamId) {
        streamsLock.lock();
        streamDataHashMap.put(streamId, new Stream(streamId));
        streamsLock.unlock();
    }

    public int openHSStream(short streamId, int port) {
        return openStream(streamId, "", port);
    }

    public static final int STREAM_SUCCESSFUL = 0;
    public static final int STREAM_FAILURE_UNKNOWN = -1;

    public int openStream(short streamId, String address, int port) {
        addStream(streamId);
        sendCell(new BeginCommand(circuitId, streamId, address, port));
        RelayCell relayCell = waitForRelayCell(streamId, RelayCell.CONNECTED, RelayCell.END);
        return relayCell instanceof ConnectedCommand ? STREAM_SUCCESSFUL : relayCell instanceof EndCommand endCommand ? endCommand.getReason() : STREAM_FAILURE_UNKNOWN;
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
        guard.removeCircuit(circuitId);
        if (terminateGuard) guard.terminate();
        return success;
    }

    public void destroyed(byte reason) {
        connected = reason;
    }

    public boolean truncate(int level) {
        // Levels here start from 0, since you can't truncate zero nodes and so there's no point in starting from 1.
        truncateLock.lock();
        sendRelayCell(new TruncateCommand(circuitId), relayKeys.size() - 2 - level);

        for (int i = 0; i < level + 1; i++) {
            relays.removeLast();
            relayKeys.removeLast();
        }
        truncateLock.unlock();
        TruncatedCommand truncatedCommand = waitForRelayCell((short) 0, RelayCell.TRUNCATED);
        return truncatedCommand.getReason() == DestroyCell.DestroyReason.REQUESTED.getReason();
    }

    public byte getConnected() {
        return connected;
    }

    public int getCircuitId() {
        return circuitId;
    }
}
