package snowy.autumn.tor.directory;

import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.cell.cells.relay.commands.DataCommand;
import snowy.autumn.tor.cell.cells.relay.commands.EndCommand;
import snowy.autumn.tor.circuit.Circuit;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class Directory {

    public enum Authorities {
        MORIA1("moria1", "128.31.0.39", 9201),
        TOR26("tor26", "217.196.147.77", 443),
        DIZUM("dizum", "45.66.35.11", 443),
        GABELMOO("gabelmoo", "131.188.40.189", 443),
        DANNEBENG("dannenberg", "193.23.244.244", 443),
        MAATUSKA("maatuska", "171.25.193.9", 80),
        LONGCLAW("longclaw", "199.58.81.140", 443),
        BASTET("bastet", "204.13.164.118", 443),
        FARAVAHAR("faravahar", "216.218.219.41", 443);

        private final String name;
        private final String ipv4;
        private final int orport;

        Authorities(String name, String ipv4, int orport) {
            this.name = name;
            this.ipv4 = ipv4;
            this.orport = orport;
        }

        public String getIpv4() {
            return ipv4;
        }

        public int getORPort() {
            return orport;
        }
    }

    Circuit circuit;
    Random random = new Random();
    Guard guard;
    MicrodescConsensus microdescConsensus;
    RouterMicrodesc directoryMicrodesc;

    public Directory(MicrodescConsensus microdescConsensus, RouterMicrodesc directoryMicrodesc, Circuit circuit) {
        this.microdescConsensus = microdescConsensus;
        this.directoryMicrodesc = directoryMicrodesc;
        this.circuit = circuit;
    }

    public Directory(String host, int port) {
        this.guard = new Guard(host, port, new byte[20]);
    }

    public boolean extendToDirectory() {
        if (directoryMicrodesc == null) return false;
        if (circuit == null || !circuit.isConnected()) return false;
        return circuit.extend2(directoryMicrodesc);
    }

    public boolean prepareCircuit() {
        if (!guard.connect()) return false;
        if (!guard.generalTorHandshake()) return false;
        guard.startCellListener();
        this.circuit = new Circuit(random.nextInt(), guard);
        return circuit.createFast();
    }

    protected String httpRequest(String request) {
        short streamId = (short) random.nextInt();
        if (!circuit.openDirStream(streamId)) return null;
        circuit.sendData(streamId, request.getBytes());
        RelayCell relayCell;
        StringBuilder response = new StringBuilder();
        while (true) {
            relayCell = circuit.waitForRelayCell(streamId, RelayCell.DATA, RelayCell.END);
            if (relayCell == null) return null;
            if (relayCell instanceof EndCommand) break;
            response.append(new String(((DataCommand) relayCell).getData()));
        }
        if (((EndCommand) relayCell).getReason() == EndCommand.EndReason.REASON_DONE.getReason())
            return response.toString();
        return null;
    }

    public MicrodescConsensus fetchMicrodescConsensus(DirectoryKeys authDirectoryKeys) {
        if (circuit == null) throw new Error("Cannot fetch any type of consensus when the circuit is null.");
        String consensus = httpRequest("GET /tor/status-vote/current/consensus-microdesc/D586D1+14C131+E8A9C4+ED03BB+0232AF+49015F+EFCBE7+23D15D+27102B HTTP/1.0\r\n\r\n");
        if (consensus == null) return microdescConsensus = null;
        consensus = Arrays.stream(consensus.replaceAll("\r\n", "\n").split("\n\n")).toList().getLast();
        return MicrodescConsensus.parse(authDirectoryKeys, consensus);
    }

    public boolean fetchMicrodescriptors(List<RouterMicrodesc> microdescs) {
        String requestPath = String.join("-", microdescs.stream().map(RouterMicrodesc::getMicrodescHash).toList());
        String response = httpRequest("GET /tor/micro/d/" + requestPath + " HTTP/1.0\r\n\r\n");
        if (response == null) return false;
        String[] microdescriptors = response.substring(response.indexOf("onion-key\n") + "onion-key\n".length()).split("onion-key\n");
        if (microdescriptors.length != microdescs.size())
            return false; // Ideally we'd want to be able to identify which one is missing but for now we'll treat it as a failure.

        for (int i = 0; i < microdescriptors.length; i++) {
            if (!microdescs.get(i).updateFromMicrodesc(microdescriptors[i]))
                throw new RuntimeException("Microdesc hash didn't match for microdesc with advertised microdesc hash `" + microdescs.get(i) + '`');
        }

        return true;
    }

    public boolean fetchMicrodescriptors(MicrodescConsensus microdescConsensus) {
        return microdescConsensus.fetchMicrodescriptors(this);
    }

    public void updateCircuit(MicrodescConsensus microdescConsensus) {
        circuit.updateFromConsensus(microdescConsensus);
    }

    public boolean destroyCircuit() {
        return circuit.destroy(true);
    }

}
