package snowy.autumn.tor.client;

import snowy.autumn.tor.circuit.Circuit;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;
import snowy.autumn.tor.relay.Handshakes;

import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.concurrent.locks.ReentrantLock;

public class CircuitManager {

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
        int circuitId;
        do circuitId = Circuit.getValidCircuitId(random.nextInt());
        while (circuitHashMap.containsKey(circuitId));
        return circuitId;
    }

    private RouterMicrodesc getPotentialExit(int port, RouterMicrodesc... usedRouters) {
        List<RouterMicrodesc> microdescs = MicrodescConsensus.getAllWithExitPolicy(
                MicrodescConsensus.getAllExcept(clientState.microdescConsensus.getMicrodescs(), usedRouters), port
        );
        return microdescs.get(random.nextInt(microdescs.size()));
    }

    private long longFromCircuitAndStream(int circuitId, short streamId) {
        return ((long) circuitId << 16) | streamId;
    }

    public int createConnectionCircuit(int port) {
        // Acquire the circuits lock to allow multithreading activity.
        circuitsLock.lock();
        // Generate a new random circuit id.
        int circuitId = getUnusedCircuitId();
        // Get a random primary guard.
        Guard.GuardInfo guardInfo = clientState.vanguardsLite.getEntryGuard();
        // Create a new circuit using that guard.
        Circuit circuit = new Circuit(circuitId, guardInfo.guard());
        // Attempt to initialise the circuit with an NTORv3 handshake.
        boolean created = circuit.create2(guardInfo.guardMicrodesc(), Handshakes.NTORv3);
        if (!created) throw new RuntimeException("Unhandled for now circuit creation exception.");
        // Get a new second layer vanguard router microdesc.
        RouterMicrodesc secondLayerMicrodesc = clientState.vanguardsLite.getSecondLayerVanguard();
        // Extend the circuit.
        boolean extended = circuit.extend2(secondLayerMicrodesc);
        if (!extended) throw new RuntimeException("Unhandled for now circuit extension exception.");
        // Get a potential exit.
        RouterMicrodesc exitMicrodesc = getPotentialExit(port, guardInfo.guardMicrodesc(), secondLayerMicrodesc);
        // Extend the circuit.
        extended = circuit.extend2(exitMicrodesc);
        if (!extended) throw new RuntimeException("Unhandled for now circuit exit extension exception.");
        // Add the circuit to the hashmap.
        circuitHashMap.put(circuitId, circuit);
        // Release the lock.
        circuitsLock.unlock();
        // Return the circuit id.
        return circuitId;
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

}
