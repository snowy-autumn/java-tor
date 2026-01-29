package snowy.autumn.tor.client;

import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.cell.cells.relay.commands.DataCommand;
import snowy.autumn.tor.cell.cells.relay.commands.EndCommand;
import snowy.autumn.tor.circuit.Circuit;

import java.util.concurrent.locks.ReentrantLock;

public class ConnectionIO {

    boolean connected;
    ReentrantLock writeLock = new ReentrantLock();
    ReentrantLock readLock = new ReentrantLock();
    Circuit circuit;
    short streamId;

    public ConnectionIO(Circuit circuit, short streamId) {
        this.circuit = circuit;
        this.streamId = streamId;
        this.connected = true;
    }

    public boolean write(byte[] data) {
        if (!(connected = connected && circuit.isConnected())) return false;
        writeLock.lock();
        try {
            return circuit.sendData(streamId, data);
        }
        finally {
            writeLock.unlock();
        }
    }

    public byte[] read() {
        if (!(connected = connected && circuit.isConnected())) return null;
        readLock.lock();
        RelayCell relayCell = circuit.waitForRelayCell(streamId, RelayCell.DATA, RelayCell.END);
        byte[] data = null;
        if (relayCell instanceof DataCommand dataCommand)
            data = dataCommand.getData();
        else if (relayCell instanceof EndCommand endCommand)
            connected = false;

        try {
            return data;
        }
        finally {
            readLock.unlock();
        }
    }

    public byte getConnected() {
        return circuit.getConnected();
    }

    public boolean isConnected() {
        return connected;
    }

    public void close() {
        connected = false;
        circuit.sendRelayCell(new EndCommand(circuit.getCircuitId(), streamId, EndCommand.EndReason.REASON_DONE.getReason()));
    }

}
