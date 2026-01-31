package snowy.autumn.tor.directory;

import org.bouncycastle.util.encoders.Hex;
import snowy.autumn.tor.cell.cells.relay.RelayCell;
import snowy.autumn.tor.cell.cells.relay.commands.DataCommand;
import snowy.autumn.tor.cell.cells.relay.commands.EndCommand;
import snowy.autumn.tor.circuit.Circuit;
import snowy.autumn.tor.directory.documents.DirectoryKeyNetDoc;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;

public class Directory {

    public enum Authorities {
        MORIA1("moria1", "128.31.0.39", 9201, Hex.decode("F533C81CEF0BC0267857C99B2F471ADF249FA232")),
        TOR26("tor26", "217.196.147.77", 443, Hex.decode("2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C")),
        DIZUM("dizum", "45.66.35.11", 443, Hex.decode("E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58")),
        GABELMOO("gabelmoo", "131.188.40.189", 443, Hex.decode("ED03BB616EB2F60BEC80151114BB25CEF515B226")),
        DANNEBENG("dannenberg", "193.23.244.244", 443, Hex.decode("0232AF901C31A04EE9848595AF9BB7620D4C5B2E")),
        MAATUSKA("maatuska", "171.25.193.9", 80, Hex.decode("49015F787433103580E3B66A1707A00E60F2D15B")),
        LONGCLAW("longclaw", "199.58.81.140", 443, Hex.decode("23D15D965BC35114467363C165C4F724B64B4F66")),
        BASTET("bastet", "204.13.164.118", 443, Hex.decode("27102BC123E7AF1D4741AE047E160C91ADC76B21")),
        FARAVAHAR("faravahar", "216.218.219.41", 443, Hex.decode("70849B868D606BAECFB6128C5E3D782029AA394F"));
        // Note: Another authority exists named 'Serge', but it's a bridge authority, and so it shouldn't be included here, since this implementation does not support bridges at the moment.

        private final String name;
        private final String ipv4;
        private final int orport;
        byte[] fingerprint;

        Authorities(String name, String ipv4, int orport, byte[] fingerprint) {
            this.name = name;
            this.ipv4 = ipv4;
            this.orport = orport;
            this.fingerprint = fingerprint;
        }

        public String getIpv4() {
            return ipv4;
        }

        public int getORPort() {
            return orport;
        }

        public byte[] getFingerprint() {
            return fingerprint;
        }

        public String getName() {
            return name;
        }
    }

    Circuit circuit;
    Random random = new Random();
    Guard guard;
    protected MicrodescConsensus microdescConsensus;
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
        if (guard == null) return true; // This is true since this only happens when the directory instance has been initialised with a circuit directly.
        if (!guard.connect()) return false;
        if (!guard.generalTorHandshake()) return false;
        guard.startCellListener();
        this.circuit = new Circuit(random.nextInt(), guard);
        return circuit.createFast();
    }

    protected String httpRequest(String request) {
        return httpRequest(request, null);
    }

    protected String httpRequest(String request, MicrodescConsensus microdescConsensus) {
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
            if (microdescConsensus != null) {
                String paramsSubstring = response.toString().replaceAll("\r\n", "\n");
                int index = paramsSubstring.indexOf("\nparams ");
                int paramsEnd = paramsSubstring.indexOf('\n', index + 1);
                if (index != -1 && paramsEnd != -1) {
                    paramsSubstring = paramsSubstring.substring(index, paramsEnd);
                    MicrodescConsensus.parseMicrodescConsensusParams(paramsSubstring, microdescConsensus);
                    // Note: This is done in order to prevent the directory from tearing the connection for the reason of protocol violation,
                    // since the consensus might contain a different minimum send_me version (1) than the default, which is 0.
                    circuit.updateFromConsensus(microdescConsensus);
                    microdescConsensus = null;
                }
            }
        }
        if (((EndCommand) relayCell).getReason() == EndCommand.EndReason.REASON_DONE.getReason())
            return response.toString();
        return null;
    }

    public DirectoryKeyNetDoc fetchDirectoryKeyCertsNetDoc(byte[] fingerprint) {
        if (circuit == null) throw new Error("Cannot fetch any net-doc when the circuit is null.");
        String netdoc = httpRequest("GET /tor/keys/fp/" + HexFormat.of().formatHex(fingerprint).toUpperCase() + " HTTP/1.0\r\n\r\n");
        if (netdoc == null) return null;
        netdoc = Arrays.stream(netdoc.replaceAll("\r\n", "\n").split("\n\n")).toList().getLast();
        return DirectoryKeyNetDoc.parse(netdoc, fingerprint);
    }

    public DirectoryKeys fetchAuthorityKeys() {
        DirectoryKeyNetDoc[] keys = new DirectoryKeyNetDoc[Authorities.values().length];
        for (int i = 0; i < keys.length; i++) {
            Authorities authority = Authorities.values()[i];
            DirectoryKeyNetDoc authorityKeys = fetchDirectoryKeyCertsNetDoc(authority.getFingerprint());
            if (authorityKeys == null) throw new RuntimeException("Failed to fetch authority directory key certs for authority '" + authority.getName() + "'.");
            keys[i] = authorityKeys;
        }
        return new DirectoryKeys(keys);
    }

    public MicrodescConsensus fetchMicrodescConsensus(DirectoryKeys authDirectoryKeys) {
        if (circuit == null) throw new Error("Cannot fetch any type of consensus when the circuit is null.");
        MicrodescConsensus microdescConsensus = new MicrodescConsensus();
        String consensus = httpRequest("GET /tor/status-vote/current/consensus-microdesc/F533C8+2F3DF9+E8A9C4+ED03BB+0232AF+49015F+23D15D+27102B+70849B HTTP/1.0\r\n\r\n", microdescConsensus);
        if (consensus == null) return microdescConsensus = null;
        consensus = Arrays.stream(consensus.replaceAll("\r\n", "\n").split("\n\n")).toList().getLast();
        MicrodescConsensus.parse(authDirectoryKeys, consensus, microdescConsensus);
        return microdescConsensus;
    }

    public boolean fetchMicrodescriptors(List<RouterMicrodesc> microdescs) {
        String requestPath = String.join("-", microdescs.stream().map(RouterMicrodesc::getEncodedMicrodescHash).toList());
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

    @Override
    public String toString() {
        if (directoryMicrodesc != null)
            return directoryMicrodesc.getHost() + ":" + directoryMicrodesc.getPort();
        return guard.getHost() + ":" + guard.getPort();
    }
}
