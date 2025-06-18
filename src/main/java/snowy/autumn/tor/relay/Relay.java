package snowy.autumn.tor.relay;

import snowy.autumn.tor.circuit.Circuit;

public class Relay {

    int deliverWindow = 1000;
    int total = 0;

    String host;
    int port;
    byte[] rsaId;

    public Relay(String host, int port, byte[] rsaId) {
        this.host = host;
        this.port = port;
        this.rsaId = rsaId;
    }

    public void received(Circuit circuit) {
        total++;
        if (--deliverWindow <= 900) {
            circuit.handleSendMe((short) 0);
            deliverWindow += 100;
        }
    }

}
