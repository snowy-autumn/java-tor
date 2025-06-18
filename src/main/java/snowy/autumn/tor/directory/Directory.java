package snowy.autumn.tor.directory;

import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.cell.cells.relay.commands.DataCommand;
import snowy.autumn.tor.cell.cells.relay.commands.EndCommand;
import snowy.autumn.tor.circuit.Circuit;
import snowy.autumn.tor.relay.Guard;

import java.util.Random;

public class Directory {

    Circuit circuit;
    Random random = new Random();
    Guard guard;

    public Directory(String host, int port, byte[] rsaId) {
        this.guard = new Guard(host, port, rsaId);
    }

    public boolean prepareCircuit() {
        if (!guard.connect()) return false;
        if (!guard.generalTorHandshake()) return false;
        guard.startCellListener();
        this.circuit = new Circuit(random.nextInt(), guard);
        return circuit.createFast();
    }

    public Consensus fetchConsensus() {
        if (circuit == null) throw new Error("Cannot fetch a consensus when the circuit is null.");
        short streamId = (short) random.nextInt();
        if (!circuit.openDirStream(streamId)) return null;
        circuit.sendCell(new DataCommand(circuit.getCircuitId(), streamId, "GET /tor/status-vote/current/consensus-microdesc/D586D1+14C131+E8A9C4+ED03BB+0232AF+49015F+EFCBE7+23D15D+27102B HTTP/1.0\r\n\r\n".getBytes()));
        RelayCell relayCell;
        StringBuilder consensus = new StringBuilder();
        while (true) {
            relayCell = circuit.waitForRelayCell(streamId, RelayCell.DATA, RelayCell.END);
            if (relayCell == null) return null;
            if (relayCell instanceof EndCommand) break;
            consensus.append(new String(((DataCommand) relayCell).getData()));
        }
        if (((EndCommand) relayCell).getReason() == EndCommand.REASON_DONE)
            return Consensus.parse(consensus.toString());
        return null;
    }

    public boolean destroyCircuit() {
        return circuit.destroy();
    }

}
