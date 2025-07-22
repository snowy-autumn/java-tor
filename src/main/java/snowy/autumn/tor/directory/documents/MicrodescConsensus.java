package snowy.autumn.tor.directory.documents;

import snowy.autumn.tor.hs.HiddenService;

import java.util.*;
import java.util.stream.Collectors;

public class MicrodescConsensus {

    HashMap<String, Integer> params = new HashMap<>();
    ArrayList<RouterMicrodesc> microdescs = new ArrayList<>();
    ArrayList<HiddenService.HSDir> hsDirs = new ArrayList<>();

    // SRV - Shared Random Value
    byte[] previousSRV = new byte[32];
    byte[] currentSRV = new byte[32];

    public MicrodescConsensus() {
        // Default params: these params might be changed according to values from the consensus, but unless they're present these should be at their default values.
        params.put("hsdir_n_replicas", 2);
        params.put("hsdir_spread_fetch", 3);
        params.put("hsdir_spread_store", 4);
    }

    public MicrodescConsensus(HashMap<String, Integer> params) {
        this.params = params;
    }

	public MicrodescConsensus(byte[] previousSRV, byte[] currentSRV, HashMap<String, Integer> params, ArrayList<RouterMicrodesc> microdescs) {
		this(params);
		this.previousSRV = previousSRV;
		this.currentSRV = currentSRV;
		this.microdescs = microdescs;
        Collections.shuffle(this.microdescs);
        for (RouterMicrodesc microdesc : this.microdescs) {
            if (microdesc.isFlag(RouterMicrodesc.Flags.HS_DIR))
                hsDirs.add(new HiddenService.HSDir(microdesc, new byte[0]));
        }
	}

    public static MicrodescConsensus parse(String consensusData) {
        MicrodescConsensus microdescConsensus = new MicrodescConsensus();

        int paramsStart = consensusData.indexOf("\nparams ") + 8;
        String params = consensusData.substring(paramsStart, consensusData.indexOf('\n', paramsStart));

        for (String param : params.split(" ")) {
            microdescConsensus.params.put(param.split("=")[0], Integer.valueOf(param.split("=")[1]));
        }

        // Parsing the known-flags listing.
        int startKnownFlags = consensusData.indexOf("\nknown-flags ");
        int endKnownFlags = consensusData.indexOf("\n", startKnownFlags + 1);
        Set<String> knownFlags = Arrays.stream(consensusData.substring(startKnownFlags, endKnownFlags).trim().split(" ")).collect(Collectors.toSet());

        // Parsing the random shared secrets. (We'll assume they're adjacent in the consensus)
        int prevSRVStart = consensusData.indexOf("\nshared-rand-previous-value");
        int currentSRVStart = consensusData.indexOf("\nshared-rand-current-value", prevSRVStart);
        String[] SRVs = consensusData.substring(prevSRVStart + 1, consensusData.indexOf('\n', currentSRVStart + 1)).split("\n");
        // According to the 'Shared Random Subsystem' spec, the previous SRV value should be listed before the current one.
        // SRVs are listed in this format: "shared-rand-value" NUM_REVEALS VALUE NL, so the value will always be the third one.
        microdescConsensus.previousSRV = Base64.getDecoder().decode(SRVs[0].split(" ")[2]);
        microdescConsensus.currentSRV = Base64.getDecoder().decode(SRVs[1].split(" ")[2]);

        // Parsing the relays listed in the microdesc-consensus.
        String[] routerMicrodescRefs = consensusData.substring(consensusData.indexOf("\nr ") + 3, consensusData.indexOf("\ndirectory-footer")).split("\nr ");
        for (String ref : routerMicrodescRefs) {
            String[] routerInfo = ref.substring(0, ref.indexOf('\n')).split(" ");
            byte[] fingerprint = Base64.getDecoder().decode(routerInfo[1]);
            String host = routerInfo[4];
            int port = Integer.parseInt(routerInfo[5]);
            String microdescHash = ref.substring(ref.indexOf("\nm ") + 3).split("\n")[0];

            // I'm not sure whether I'm supposed to do this, but since I don't think we'll ever be in a situation where this would occur, then I've added it anyway.
            String statusFlags = ref.substring(ref.indexOf("\ns ") + 3).split("\n")[0].strip();
            if (!Arrays.stream(statusFlags.split(" ")).allMatch(knownFlags::contains)) continue;
            statusFlags = statusFlags.toLowerCase();

            String[] routerIpv6Info = new String[2];

            if (ref.contains("\na "))
                routerIpv6Info = ref.substring(ref.indexOf("\na ") + 3).split("\n")[0].substring(1).split("]:");

            // We'll check whether the node is listed as Stable, Running and Valid.
            if (!(statusFlags.contains("stable") && statusFlags.contains("running") && statusFlags.contains("valid"))) continue;
            RouterMicrodesc microdesc = new RouterMicrodesc(host, port, fingerprint, microdescHash, routerIpv6Info[0], routerIpv6Info[0] == null ? -1 : Integer.parseInt(routerIpv6Info[1]), statusFlags.split(" "));

            if (microdesc.isFlag(RouterMicrodesc.Flags.HS_DIR))
                microdescConsensus.hsDirs.add(new HiddenService.HSDir(microdesc, new byte[0]));

            microdescConsensus.microdescs.add(microdesc);
        }

        Collections.shuffle(microdescConsensus.microdescs);

        return microdescConsensus;
    }

    public void postUpdate() {
        // This is done since clients prefer to match their time periods with their SRVs.
        int hour = HiddenService.getCurrentTime().getHour();
        byte[] srv = hour >= 12 ? currentSRV : previousSRV;

        hsDirs.sort((hsDirA, hsDirB) -> Arrays.compareUnsigned(
                hsDirA.calculateHsRelayIndexConditional(srv),
                hsDirB.calculateHsRelayIndexConditional(srv)
        ));
    }

    public int sendMeEmitMinVersion() {
        return params.get("sendme_emit_min_version");
    }

    public int hsDirNReplicas() {
        return params.get("hsdir_n_replicas");
    }

    public int hsDirSpreadFetch() {
        return params.get("hsdir_spread_fetch");
    }

    public int hsDirSpreadStore() {
        return params.get("hsdir_spread_store");
    }

    public byte[] getPreviousSRV() {
        return previousSRV;
    }

    public byte[] getCurrentSRV() {
        return currentSRV;
    }

    public ArrayList<RouterMicrodesc> getMicrodescs() {
        return microdescs;
    }

    public HashMap<String, Integer> getParams() {
        return params;
    }

    public ArrayList<HiddenService.HSDir> getHsDirs() {
        return hsDirs;
    }

    public List<RouterMicrodesc> getAllWithFlag(byte flag) {
		return getAllWithFlag(microdescs, flag);
    }

	public static List<RouterMicrodesc> getAllWithFlag(List<RouterMicrodesc> microdescs, byte flag) {
		return microdescs.stream().filter(microdesc -> microdesc.isFlag(flag)).toList();
	}

	public static List<RouterMicrodesc> getAllWithoutFlag(List<RouterMicrodesc> microdescs, byte flag) {
		return microdescs.stream().filter(microdesc -> !microdesc.isFlag(flag)).toList();
	}

}
