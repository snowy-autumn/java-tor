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
    Consensus consensus;

    public Directory(String host, int port, byte[] fingerprint) {
        this.guard = new Guard(host, port, fingerprint);
    }

    public boolean prepareCircuit() {
        if (!guard.connect()) return false;
        if (!guard.generalTorHandshake()) return false;
        guard.startCellListener();
        this.circuit = new Circuit(random.nextInt(), guard);
        return circuit.createFast();
    }

    private String httpRequest(String request) {
        short streamId = (short) random.nextInt();
        if (!circuit.openDirStream(streamId)) return null;
        circuit.sendCell(new DataCommand(circuit.getCircuitId(), streamId, request.getBytes()));
        RelayCell relayCell;
        StringBuilder response = new StringBuilder();
        while (true) {
            relayCell = circuit.waitForRelayCell(streamId, RelayCell.DATA, RelayCell.END);
            if (relayCell == null) return null;
            if (relayCell instanceof EndCommand) break;
            response.append(new String(((DataCommand) relayCell).getData()));
        }
        if (((EndCommand) relayCell).getReason() == EndCommand.REASON_DONE)
            return response.toString();
        return null;
    }

    public Consensus fetchConsensus() {
        if (circuit == null) throw new Error("Cannot fetch a consensus when the circuit is null.");
        String consensus = httpRequest("GET /tor/status-vote/current/consensus-microdesc/D586D1+14C131+E8A9C4+ED03BB+0232AF+49015F+EFCBE7+23D15D+27102B HTTP/1.0\r\n\r\n");
        return consensus == null ? null : Consensus.parse(consensus);
    }

    public boolean destroyCircuit() {
        return circuit.destroy();
    }

}
