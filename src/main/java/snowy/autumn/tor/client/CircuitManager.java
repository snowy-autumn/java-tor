package snowy.autumn.tor.client;

import snowy.autumn.tor.cell.cells.relay.commands.IntroduceAckCommand;
import snowy.autumn.tor.circuit.CanExtendTo;
import snowy.autumn.tor.circuit.Circuit;
import snowy.autumn.tor.crypto.KeyPair;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.hs.HSDirectory;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.hs.HiddenServiceDescriptor;
import snowy.autumn.tor.hs.IntroductionPoint;
import snowy.autumn.tor.relay.Guard;
import snowy.autumn.tor.relay.Handshakes;

import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.concurrent.locks.ReentrantLock;

public class CircuitManager {

    public record RendezvousInfo(int circuitId, RouterMicrodesc rendezvousPoint, byte[] rendezvousCookie) {}

    TorClient.ClientState clientState;
    Random random;
    HashMap<Integer, Circuit> circuitHashMap = new HashMap<>();
    HashMap<Long, ConnectionInfo> connectionInfoHashMap = new HashMap<>();
    ReentrantLock circuitsLock = new ReentrantLock();
    ReentrantLock streamsLock = new ReentrantLock();

    public CircuitManager(TorClient.ClientState clientState) {
        this.clientState = clientState;
        this.random = new Random();
    }

    private int getUnusedCircuitId() {
        boolean holder = circuitsLock.isHeldByCurrentThread();
        if (!circuitsLock.isLocked())
            circuitsLock.lock();
        int circuitId;
        do {
            circuitId = Circuit.getValidCircuitId(random.nextInt());
            if (circuitHashMap.containsKey(circuitId) && !circuitHashMap.get(circuitId).isConnected())
                circuitHashMap.remove(circuitId);
        }
        while (circuitHashMap.containsKey(circuitId));
        if (!holder && circuitsLock.isHeldByCurrentThread())
            circuitsLock.unlock();
        return circuitId;
    }

    private RouterMicrodesc getRandomRouterMicrodesc() {
        List<RouterMicrodesc> microdescs = clientState.microdescConsensus.getMicrodescs();
        return microdescs.get(random.nextInt(microdescs.size()));
    }

    private RouterMicrodesc getPotentialExit(int port, RouterMicrodesc... usedRouters) {
        List<RouterMicrodesc> microdescs = MicrodescConsensus.getAllExcept(clientState.microdescConsensus.getMicrodescs(), usedRouters);
        if (port != -1) microdescs = MicrodescConsensus.getAllWithExitPolicy(microdescs, port);
        return microdescs.get(random.nextInt(microdescs.size()));
    }

    private long longFromCircuitAndStream(int circuitId, short streamId) {
        return ((long) circuitId << 16) | streamId;
    }

    public int createDefaultCircuit(int port, CanExtendTo lastNode) {
        // Note: If a lastNode is given, then specifying a port would not have an effect on the circuit.
        // Acquire the circuits lock to allow multithreading activity.
        circuitsLock.lock();
        // Generate a new random circuit id.
        int circuitId = getUnusedCircuitId();
        // Get a random primary guard.
        Guard.GuardInfo guardInfo = clientState.vanguardsLite.getEntryGuard(lastNode);
        // Create a new circuit using that guard.
        Circuit circuit = new Circuit(circuitId, guardInfo.guard());
        // Attempt to initialise the circuit with an NTORv3 handshake.
        boolean created = circuit.create2(guardInfo.guardMicrodesc(), Handshakes.NTORv3);
        if (!created) throw new RuntimeException("Unhandled for now circuit creation exception.");
        // Get a new second layer vanguard router microdesc.
        RouterMicrodesc secondLayerMicrodesc = clientState.vanguardsLite.getSecondLayerVanguard(lastNode);
        // Extend the circuit.
        boolean extended = circuit.extend2(secondLayerMicrodesc);
        if (!extended) throw new RuntimeException("Unhandled for now circuit extension exception.");
        // If lastNode is null, then we need to find a proper potential exit. If the given port is -1, then this circuit is not an exit circuit.
        if (lastNode == null)
            lastNode = getPotentialExit(port, guardInfo.guardMicrodesc(), secondLayerMicrodesc);
        // Extend the circuit.
        extended = circuit.extend2(lastNode);
        if (!extended) throw new RuntimeException("Unhandled for now circuit exit extension exception.");
        // Add the circuit to the hashmap.
        circuitHashMap.put(circuitId, circuit);
        // Release the lock.
        circuitsLock.unlock();
        // Return the circuit id.
        return circuitId;
    }

    public int createDefaultCircuit(int port) {
        // Create a default circuit with an unspecified exit.
        return createDefaultCircuit(port, null);
    }

    public ConnectionInfo connectWithCircuit(int circuitId, String host, int port) {
        // Acquire the circuits lock to allow multithreading activity.
        circuitsLock.lock();
        // Attempt to get the circuit from the hashmap.
        Circuit circuit;
        if (circuitHashMap.containsKey(circuitId))
            circuit = circuitHashMap.get(circuitId);
        else throw new RuntimeException("Attempted to get a non-existent circuit.");
        // Attempt to open a stream to the target.
        short streamId = (short) random.nextInt();
        int streamStatus = circuit.openStream(streamId, host, port);
        // Get long representation of circuit and stream.
        long circuitStreamId = longFromCircuitAndStream(circuitId, streamId);
        ConnectionInfo connectionInfo = new ConnectionInfo(new ConnectionIO(circuit, streamId), (byte) streamStatus);
        // Release the lock.
        circuitsLock.unlock();
        // If the connection failed, then return connectionInfo now.
        if (!connectionInfo.isConnected())
            return connectionInfo;
        // Acquire the streams lock.
        streamsLock.lock();
        // Put connectionInfo in the connectionInfos hashmap.
        connectionInfoHashMap.put(circuitStreamId, connectionInfo);
        // Release the lock.
        streamsLock.unlock();
        // Return connectionInfo.
        return connectionInfo;
    }

    public ConnectionInfo connectHSWithCircuit(int circuitId, int port) {
        // Acquire the circuits lock to allow multithreading activity.
        circuitsLock.lock();
        // Attempt to get the circuit from the hashmap.
        Circuit circuit;
        if (circuitHashMap.containsKey(circuitId))
            circuit = circuitHashMap.get(circuitId);
        else throw new RuntimeException("Attempted to get a non-existent circuit.");
        // Attempt to open a stream to the target port.
        short streamId = (short) random.nextInt();
        int streamStatus = circuit.openHSStream(streamId, port);
        // Get long representation of circuit and stream.
        long circuitStreamId = longFromCircuitAndStream(circuitId, streamId);
        ConnectionInfo connectionInfo = new ConnectionInfo(new ConnectionIO(circuit, streamId), (byte) streamStatus);
        // Release the lock.
        circuitsLock.unlock();
        // If the connection failed, then return connectionInfo now.
        if (!connectionInfo.isConnected())
            return connectionInfo;
        // Acquire the streams lock.
        streamsLock.lock();
        // Put connectionInfo in the connectionInfos hashmap.
        connectionInfoHashMap.put(circuitStreamId, connectionInfo);
        // Release the lock.
        streamsLock.unlock();
        // Return connectionInfo.
        return connectionInfo;
    }

    public HiddenServiceDescriptor fetchHSDescriptor(HiddenService hiddenService) {
        // Get a list of possible fetch directories.
        List<RouterMicrodesc> fetchDirectories = hiddenService.possibleFetchDirectories().stream().toList();
        // Pick a random HSDirectory to fetch the HSDescriptor from.
        RouterMicrodesc hsDirMicrodesc = fetchDirectories.get(random.nextInt(fetchDirectories.size()));
        // Create a new circuit before extending to the HSDirectory.
        int circuitId = createDefaultCircuit(-1);
        // Acquire the lock.
        circuitsLock.lock();
        // Get the circuit that was created from the circuit hashmap.
        Circuit circuit = circuitHashMap.get(circuitId);
        // Release the lock.
        circuitsLock.unlock();
        // Attempt to extend to the selected HSDirectory.
        HSDirectory hsDirectory = new HSDirectory(clientState.microdescConsensus, hsDirMicrodesc, circuit);
        // If we couldn't extend to the HSDirectory for whatever reason, we return null.
        if (!hsDirectory.extendToDirectory()) return null;
        // If we managed to extend successfully, then we'll attempt to fetch the HSDescriptor from the HSDirectory.
        HiddenServiceDescriptor hsDescriptor = hsDirectory.fetchHSDescriptor(hiddenService);
        // Destroy the circuit without terminating the guard.
        circuit.destroy(false);
        // Return the fetched HSDescriptor (which would be null if it failed to fetch it).
        return hsDescriptor;
    }

    public RendezvousInfo establishRendezvous() {
        // Todo: This is probably not up to spec, so make sure that creating the circuit from the top is still what we do. (It was just easier to implement it that way)
        // Choose a random node from the consensus to become our rendezvous point.
        RouterMicrodesc rendezvousPoint = getRandomRouterMicrodesc();
        // Build a circuit to the rendezvous point.
        int rendezvousCircuitId = createDefaultCircuit(-1, rendezvousPoint);
        // Acquire the lock.
        circuitsLock.lock();
        // Get the rendezvous circuit from the hashmap.
        Circuit rendezvousCircuit = circuitHashMap.get(rendezvousCircuitId);
        // Release the lock.
        circuitsLock.unlock();
        // Attempt to do an EstablishRendezvous on the circuit and get the rendezvous cookie.
        byte[] rendezvousCookie = rendezvousCircuit.establishRendezvous();
        // If the rendezvous failed, return null.
        if (rendezvousCookie == null) return null;
        // Return the rendezvous info that will be needed to do an introduction and complete the rendezvous later.
        return new RendezvousInfo(rendezvousCircuitId, rendezvousPoint, rendezvousCookie);
    }

    public IntroduceAckCommand.IntroduceAckStatus introduce(HiddenService hiddenService, IntroductionPoint introductionPoint, RendezvousInfo rendezvousInfo) {
        // Build a circuit to the introduction point.
        int circuitId = createDefaultCircuit(-1, introductionPoint);
        // Acquire the lock.
        circuitsLock.lock();
        // Get the created circuit from the hashmap.
        Circuit circuit = circuitHashMap.get(circuitId);
        // Release the lock.
        circuitsLock.unlock();
        // Attempt to send an introduce1 relay command through the introduction circuit.
        IntroduceAckCommand.IntroduceAckStatus introduceAckStatus = circuit.introduce1(introductionPoint, rendezvousInfo.rendezvousPoint(), rendezvousInfo.rendezvousCookie(), hiddenService);
        // Destroy the introduction circuit without terminating the guard.
        circuit.destroy(false);
        // Return the IntroduceAck status.
        return introduceAckStatus;
    }

    public boolean finishRendezvous(int circuitId, IntroductionPoint introductionPoint, KeyPair keyPair) {
        // Acquire the lock.
        circuitsLock.lock();
        // Get the rendezvous circuit from the hashmap.
        Circuit circuit = circuitHashMap.get(circuitId);
        // Release the lock.
        circuitsLock.unlock();
        // Attempt to complete the rendezvous with the hidden service and return whether it was successful.
        return circuit.rendezvous(keyPair, introductionPoint);
    }

    public void tearCircuit(int circuitId) {
        // Acquire the lock.
        circuitsLock.lock();
        // Get the circuit from the hashmap.
        Circuit circuit = circuitHashMap.get(circuitId);
        // Release the lock.
        circuitsLock.unlock();
        // If the circuit is null, return.
        if (circuit == null) return;
        // Destroy the circuit without terminating the guard.
        circuit.destroy(false);
    }

}
