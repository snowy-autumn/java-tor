package snowy.autumn.tor.directory.documents;

import java.util.*;

public class MicrodescConsensus {

    HashMap<String, Integer> params = new HashMap<>();
    ArrayList<RouterMicrodesc> microdescs = new ArrayList<>();

    public MicrodescConsensus() {

    }

    public MicrodescConsensus(HashMap<String, Integer> params) {
        this.params = params;
    }

    public static MicrodescConsensus parse(String consensusData) {
        MicrodescConsensus microdescConsensus = new MicrodescConsensus();

        int paramsStart = consensusData.indexOf("\nparams ") + 8;
        String params = consensusData.substring(paramsStart, consensusData.indexOf('\n', paramsStart));

        for (String param : params.split(" ")) {
            microdescConsensus.params.put(param.split("=")[0], Integer.valueOf(param.split("=")[1]));
        }

        String[] routerMicrodescRefs = consensusData.substring(consensusData.indexOf("\nr ") + 3, consensusData.indexOf("\ndirectory-footer")).split("\nr ");
        for (String ref : routerMicrodescRefs) {
            String[] routerInfo = ref.substring(0, ref.indexOf('\n')).split(" ");
            byte[] fingerprint = Base64.getDecoder().decode(routerInfo[1]);
            String host = routerInfo[4];
            int port = Integer.parseInt(routerInfo[5]);
            String microdescHash = ref.substring(ref.indexOf("\nm ") + 3).split("\n")[0];
            microdescConsensus.microdescs.add(new RouterMicrodesc(host, port, fingerprint, microdescHash));
        }

        Collections.shuffle(microdescConsensus.microdescs);

        return microdescConsensus;
    }

    public int sendMeEmitMinVersion() {
        return params.get("sendme_emit_min_version");
    }

    public ArrayList<RouterMicrodesc> getMicrodescs() {
        return microdescs;
    }
}
