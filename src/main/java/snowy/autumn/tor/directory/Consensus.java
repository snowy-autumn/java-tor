package snowy.autumn.tor.directory;

import java.util.HashMap;

public class Consensus {

    HashMap<String, Integer> params = new HashMap<>();

    public Consensus() {

    }

    public Consensus(HashMap<String, Integer> params) {
        this.params = params;
    }

    public static Consensus parse(String consensusData) {
        Consensus consensus = new Consensus();
        String[] lines = consensusData.split("\n");
        for (String line : lines) {
            if (line.strip().startsWith("params")) {
                String[] params = line.split(" ");
                for (int i = 1; i < params.length; i++) {
                    String parameter = params[i].split("=")[0];
                    int value = Integer.parseInt(params[i].split("=")[1]);
                    consensus.params.put(parameter, value);
                }
            }
        }
        return consensus;
    }

    public int sendMeEmitMinVersion() {
        return params.get("sendme_emit_min_version");
    }

}
