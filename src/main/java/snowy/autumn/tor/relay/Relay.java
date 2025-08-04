package snowy.autumn.tor.relay;

import snowy.autumn.tor.circuit.Circuit;

import java.util.HashMap;

public class Relay {

    HashMap<Integer, Integer> deliverWindows = new HashMap<>();

    String host;
    int port;
    byte[] fingerprint;

    public Relay(String host, int port, byte[] fingerprint) {
        this.host = host;
        this.port = port;
        this.fingerprint = fingerprint;
    }

    public void initialiseDeliverWindow(int circuitId) {
        // Todo: Change this from a fixed size of 1000 to whatever is the value of the consensus parameter 'circwindow'.
        this.deliverWindows.put(circuitId, 1000);
    }

    public void received(Circuit circuit, byte[] digest) {
        int deliverWindow = deliverWindows.get(circuit.getCircuitId());
        if (--deliverWindow <= 900) {
            circuit.handleSendMe((short) 0, digest);
            deliverWindow += 100;
        }
        deliverWindows.put(circuit.getCircuitId(), deliverWindow);
    }

}
