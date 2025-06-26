package snowy.autumn.tor.directory.documents;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;

public class MicrodescConsensus {

    HashMap<String, Integer> params = new HashMap<>();
    ArrayList<RouterMicrodesc> microdescs = new ArrayList<>();
    ArrayList<RouterMicrodesc> potentialGuards = new ArrayList<>();
    ArrayList<RouterMicrodesc> fastNodes = new ArrayList<>();
    ArrayList<RouterMicrodesc> potentialExits = new ArrayList<>();

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

            // Todo: verify the all flags are listed in the consensus's known-flags listing.
            String statusFlags = ref.substring(ref.indexOf("\ns ") + 3).split("\n")[0].strip().toLowerCase();

            String[] routerIpv6Info = new String[2];

            if (ref.contains("\na "))
                routerIpv6Info = ref.substring(ref.indexOf("\na ") + 3).split("\n")[0].substring(1).split("]:");

            RouterMicrodesc microdesc = new RouterMicrodesc(host, port, fingerprint, microdescHash, routerIpv6Info[0], routerIpv6Info[0] == null ? -1 : Integer.parseInt(routerIpv6Info[1]));

            // We'll check whether the node is listed as Stable, Running and Valid.
            if (statusFlags.contains("stable") && statusFlags.contains("running") && statusFlags.contains("valid")) {
                if (statusFlags.contains("guard")) microdescConsensus.potentialGuards.add(microdesc);
                if (statusFlags.contains("exit") && !statusFlags.contains("badexit")) microdescConsensus.potentialExits.add(microdesc);
                if (statusFlags.contains("fast")) microdescConsensus.fastNodes.add(microdesc);
            }

            microdescConsensus.microdescs.add(microdesc);
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

    public HashMap<String, Integer> getParams() {
        return params;
    }
}
