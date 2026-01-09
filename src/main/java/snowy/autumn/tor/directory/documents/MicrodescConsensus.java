package snowy.autumn.tor.directory.documents;

import snowy.autumn.tor.circuit.CanExtendTo;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.directory.Directory;
import snowy.autumn.tor.directory.DirectoryKeys;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.utils.Utils;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class MicrodescConsensus {

    HashMap<String, Integer> params = new HashMap<>();
    ArrayList<RouterMicrodesc> microdescs = new ArrayList<>();
    ArrayList<HiddenService.HSDir> hsDirs = new ArrayList<>();

    // SRV - Shared Random Value
    byte[] previousSRV = new byte[32];
    byte[] currentSRV = new byte[32];

    long validAfter;
    long freshUntil;
    long validUntil;

    public MicrodescConsensus() {
        // Default params: these params might be changed according to values from the consensus, but unless they're present these should be at their default values.
        params.put("hsdir_n_replicas", 2);
        params.put("hsdir_spread_fetch", 3);
        params.put("hsdir_spread_store", 4);
    }

    public MicrodescConsensus(HashMap<String, Integer> params) {
        this.params = params;
    }

	public MicrodescConsensus(long validAfter, long freshUntil, long validUntil, byte[] previousSRV, byte[] currentSRV, HashMap<String, Integer> params, ArrayList<RouterMicrodesc> microdescs) {
		this(params);
        this.validAfter = validAfter;
        this.freshUntil = freshUntil;
        this.validUntil = validUntil;
		this.previousSRV = previousSRV;
		this.currentSRV = currentSRV;
		this.microdescs = microdescs;
        Collections.shuffle(this.microdescs);
        for (RouterMicrodesc microdesc : this.microdescs) {
            if (microdesc.isFlag(RouterMicrodesc.Flags.HS_DIR))
                hsDirs.add(new HiddenService.HSDir(microdesc, new byte[0]));
        }

        postUpdate();
	}

    public boolean fetchMicrodescriptors(Directory... directories) {
        if (directories.length < 1)
            throw new IllegalArgumentException("At least one directory needs to be passed in order to fetch microdescriptors for a microdesc-consensus.");

        int maxPerMirror = 128;
        int maxPerRequest = 92;
        // We sort them in their respective chunks in a descending order, so that we could more easily identify them later on.
        List<List<RouterMicrodesc>> chunks = IntStream.range(0, (microdescs.size() + maxPerMirror - 1) / maxPerMirror)
                .mapToObj(i -> microdescs.subList(i * maxPerMirror, Math.min(microdescs.size(), (i + 1) * maxPerMirror))
                        .stream().sorted((a, b) ->
                                Arrays.compareUnsigned(Base64.getDecoder().decode(b.getMicrodescHash()), Base64.getDecoder().decode(a.getMicrodescHash())))
                        .toList()).toList();

        for (int chunkIndex = 0; chunkIndex < chunks.size(); chunkIndex++) {
            Directory directory = directories[chunkIndex % directories.length];
            List<RouterMicrodesc> chunk = chunks.get(chunkIndex);
            if (chunk.size() > maxPerRequest) {
                List<List<RouterMicrodesc>> temporary = IntStream.range(0, 2).mapToObj(i -> chunk.subList(i * maxPerRequest, Math.min(chunk.size(), (i + 1) * maxPerRequest))).toList();
                for (List<RouterMicrodesc> sub : temporary)
                    if (!directory.fetchMicrodescriptors(sub)) return false;
            }
            else if (!directory.fetchMicrodescriptors(chunk)) return false;
        }

        postUpdate();

        return true;
    }

    private static boolean validate(DirectoryKeys authDirectoryKeys, String consensusData) {
        String signed = consensusData.substring(0, consensusData.indexOf("\ndirectory-signature ")) + "\ndirectory-signature ";
        String[] directorySignatures = consensusData.substring(consensusData.indexOf("\ndirectory-signature ") +  + "directory-signature ".length()).trim().split("directory-signature ");
        byte[] signedHash = null;
        String algorithm = "";
        HashSet<DirectoryKeyNetDoc> authoritiesSigned = new HashSet<>();
        for (String directorySignature : directorySignatures) {
            String[] signatureIdParts = directorySignature.trim().split(" ");
            DirectoryKeyNetDoc directoryKeyNetDoc = authDirectoryKeys.getDirectoryKeys(signatureIdParts[1]);
            if (directoryKeyNetDoc == null) continue;
            if (!algorithm.equals(algorithm = signatureIdParts[0])) {
                if (algorithm.equalsIgnoreCase("sha256")) algorithm = "SHA-256";
                else if (algorithm.equalsIgnoreCase("sha1")) algorithm = "SHA-1";
                else continue;
                signedHash = Cryptography.createDigest(algorithm).digest(signed.getBytes());
            }
            String[] lines = directorySignature.substring(directorySignature.indexOf('\n') + 1).trim().split("\n");
            byte[] signature = Base64.getDecoder().decode(String.join("", Arrays.copyOfRange(lines, 1, lines.length - 1)));
            if (directoryKeyNetDoc.verifyRSASignature(signature, signedHash))
                authoritiesSigned.add(directoryKeyNetDoc);
        }

        return authoritiesSigned.size() * 2 >= authDirectoryKeys.getDirectoryCount();
    }

    public static void parseMicrodescConsensusParams(String params, MicrodescConsensus microdescConsensus) {
        int paramsStart = params.indexOf("\nparams ") + 8;
        int paramsEnd = params.indexOf('\n', paramsStart);
        params = params.substring(paramsStart, paramsEnd == -1 ? params.length() : paramsEnd);

        for (String param : params.split(" ")) {
            microdescConsensus.params.put(param.split("=")[0], Integer.valueOf(param.split("=")[1]));
        }
    }

    public static void parse(DirectoryKeys authDirectoryKeys, String consensusData, MicrodescConsensus microdescConsensus) {
        if (authDirectoryKeys != null && !validate(authDirectoryKeys, consensusData))
            throw new RuntimeException("Attempted to parse a microdesc consensus, but the consensus was not signed correctly.");

        microdescConsensus.validAfter = Utils.parseDate(consensusData.substring(consensusData.indexOf("valid-after ")).split("\n", 2)[0].split(" ", 2)[1]);
        microdescConsensus.freshUntil = Utils.parseDate(consensusData.substring(consensusData.indexOf("fresh-until ")).split("\n", 2)[0].split(" ", 2)[1]);
        microdescConsensus.validUntil = Utils.parseDate(consensusData.substring(consensusData.indexOf("valid-until ")).split("\n", 2)[0].split(" ", 2)[1]);

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
    }

    public void postUpdate() {
        // This is done since clients prefer to match their time periods with their SRVs.
        int hour = Utils.getCurrentTime().getHour();
        byte[] srv = hour >= 12 ? currentSRV : previousSRV;

        hsDirs.sort((hsDirA, hsDirB) -> Arrays.compareUnsigned(
                hsDirA.calculateHsRelayIndexConditional(srv),
                hsDirB.calculateHsRelayIndexConditional(srv)
        ));
    }

    public int getSendMeMinVersion() {
        int minVersion = 0; // The default value, in case the consensus doesn't specify it.
        if (params.containsKey("sendme_emit_min_version"))
            minVersion = params.get("sendme_emit_min_version");
        else if (params.containsKey("sendme_accept_min_version"))
            minVersion = params.get("sendme_accept_min_version");
        return minVersion;
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

    public long getValidAfter() {
        return validAfter;
    }

    public long getFreshUntil() {
        return freshUntil;
    }

    public long getValidUntil() {
        return validUntil;
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

    public List<RouterMicrodesc> getAllWithFlags(byte... flags) {
		return getAllWithFlags(microdescs, flags);
    }

    public RouterMicrodesc findWithHash(byte[] microdescHash) {
        return microdescs.stream().filter(microdesc -> Arrays.equals(Base64.getDecoder().decode(microdesc.getMicrodescHash()), microdescHash)).findFirst().orElse(null);
    }

	public static List<RouterMicrodesc> getAllWithFlags(List<RouterMicrodesc> microdescs, byte... flags) {
		return microdescs.stream().filter(microdesc -> microdesc.checkFlags(flags)).toList();
	}

	public static List<RouterMicrodesc> getAllWithoutFlag(List<RouterMicrodesc> microdescs, byte flag) {
		return microdescs.stream().filter(microdesc -> !microdesc.isFlag(flag)).toList();
	}

    public static List<RouterMicrodesc> getAllNonrelated(List<RouterMicrodesc> microdescs, RouterMicrodesc routerMicrodesc) {
        return microdescs.stream().filter(microdesc -> !microdesc.isRelated(routerMicrodesc)).toList();
    }

    public static List<RouterMicrodesc> getAllExcept(List<RouterMicrodesc> microdescs, CanExtendTo... routerMicrodescs) {
        return microdescs.stream().filter(microdesc -> Arrays.stream(routerMicrodescs).noneMatch(routerMicrodesc -> routerMicrodesc != null && routerMicrodesc.equals(microdesc))).toList();
    }

    public static List<RouterMicrodesc> getAllWithExitPolicy(List<RouterMicrodesc> microdescs, int port) {
        return microdescs.stream().filter(microdesc -> microdesc.getIpv4ExitPolicy() != null && microdesc.getIpv4ExitPolicy().check(port)).toList();
    }

    public boolean isValid() {
        long now = Utils.getCurrentTime().toEpochSecond();
        return now >= validAfter && now < validUntil;
    }

    public boolean isFresh() {
        long now = Utils.getCurrentTime().toEpochSecond();
        return now >= validAfter && now < freshUntil;
    }

}
