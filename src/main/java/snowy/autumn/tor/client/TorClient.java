package snowy.autumn.tor.client;

import snowy.autumn.tor.cell.cells.relay.commands.IntroduceAckCommand.IntroduceAckStatus;
import snowy.autumn.tor.circuit.Circuit;
import snowy.autumn.tor.directory.Directory;
import snowy.autumn.tor.directory.DirectoryKeys;
import snowy.autumn.tor.directory.documents.DirectoryKeyNetDoc;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.hs.HSDirectory;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.hs.HiddenServiceDescriptor;
import snowy.autumn.tor.hs.IntroductionPoint;
import snowy.autumn.tor.relay.Guard;
import snowy.autumn.tor.relay.Handshakes;
import snowy.autumn.tor.vanguards.VanguardsLayer;
import snowy.autumn.tor.vanguards.VanguardsLite;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

public class TorClient {

	private static final byte OK = 0;
	private static final byte PRE_INIT = 1;
	private static final byte FAILED_INIT_DIRECTORY_CONNECT = 2;
	private static final byte FAILED_MICRODESC_CONSENSUS_FETCH = 3;
	private static final byte FAILED_MICRODESCS_FETCH = 4;
	private static final byte NO_VALID_GUARD = 5;

	DirectoryKeys authorityKeys;
	MicrodescConsensus microdescConsensus;
    VanguardsLite vanguardsLite;

	HashMap<String, Circuit> circuitHashmap = new HashMap<>();
	ReentrantLock circuitLock = new ReentrantLock();

	Random random = new Random();

	byte clientState = PRE_INIT;

    Logger logger;

	public TorClient(boolean debug) {
        logger = new Logger(debug);
	}

    public TorClient() {
        this(false);
    }

	private static byte[] cacheMicrodesc(RouterMicrodesc microdesc) {
		byte hasIpv6 = (byte) (microdesc.hasIpv6Address() ? 1 : 0);
		byte[] ipv4ExitPolicy = microdesc.getIpv4ExitPolicy() != null ? microdesc.getIpv4ExitPolicy().serialise() : null;
		ByteBuffer buffer = ByteBuffer.allocate(1 + 4 + 2 + 20 + 96 + 1 + (hasIpv6 == 1 ? 18 : 0) + 2 + microdesc.getFamily().length * 20 + (ipv4ExitPolicy != null ? 5 + ipv4ExitPolicy.length : 1));
		// Flags
		buffer.put(microdesc.getFlags());
		// Ipv4 host
		Arrays.stream(microdesc.getHost().split("\\."))
			.forEachOrdered(i -> buffer.put((byte) Integer.parseInt(i)));
		// Ipv4 port
		buffer.putShort((short) microdesc.getPort());
		// RSA id
		buffer.put(microdesc.getFingerprint());
		// Ed25519 id
		buffer.put(microdesc.getEd25519Id());
		// Ntor onion key
		buffer.put(microdesc.getNtorOnionKey());
		// Microdesc hash
		buffer.put(Base64.getDecoder().decode(microdesc.getMicrodescHash()));
		// Ipv6 address
		buffer.put(hasIpv6);
		if (hasIpv6 == 1) {
			// host
			try {
				buffer.put(Inet6Address.getByName(microdesc.getIpv6host()).getAddress());
			}
			catch (UnknownHostException e) {
				throw new RuntimeException(e);
			}
			// port
			buffer.putShort((short) microdesc.getIpv6port());
		}
		// Family
		buffer.putShort((short) microdesc.getFamily().length);
		for (byte[] router : microdesc.getFamily()) {
			buffer.put(router);
		}
		// IPv4 exit policy
		if (ipv4ExitPolicy != null) {
			buffer.put((byte) 1);
			buffer.putInt(ipv4ExitPolicy.length);
			buffer.put(ipv4ExitPolicy);
		}
		else buffer.put((byte) 0);

		return buffer.array();
	}

	private static RouterMicrodesc parseMicrodesc(ByteBuffer buffer) {
		// parse flags
		byte flags = buffer.get();
		// parse ipv4 address
		byte[] ipv4host = new byte[4];
		buffer.get(ipv4host);
		short ipv4port = buffer.getShort();
		// parse rsa id
		byte[] fingerprint = new byte[20];
		buffer.get(fingerprint);
		// parse ed25519 id
		byte[] ed25519id = new byte[32];
		buffer.get(ed25519id);
		// parse ntor onion key
		byte[] ntorOnionKey = new byte[32];
		buffer.get(ntorOnionKey);
		// parse microdesc hash
		byte[] microdescHash = new byte[32];
		buffer.get(microdescHash);
		// parse ipv6
		boolean hasIpv6 = buffer.get() == 1;
		byte[] ipv6host = null;
		short ipv6port = -1;
		if (hasIpv6) {
			ipv6host = new byte[16];
			buffer.get(ipv6host);
			ipv6port = buffer.getShort();
		}
		// parse family
		byte[][] family = new byte[buffer.getShort()][20];
		for (int i = 0; i < family.length; i++) {
			buffer.get(family[i]);
		}
		// parse ipv4 exit policy
		RouterMicrodesc.ExitPolicy ipv4ExitPolicy = null;
		if (buffer.get() == 1) {
			byte[] ipv4ExitPolicyBytes = new byte[buffer.getInt()];
			buffer.get(ipv4ExitPolicyBytes);
			ipv4ExitPolicy = RouterMicrodesc.ExitPolicy.load(ipv4ExitPolicyBytes);
		}

		return new RouterMicrodesc(flags, ipv4host, ipv4port, fingerprint, ed25519id, ntorOnionKey, microdescHash, ipv6host, ipv6port, family, ipv4ExitPolicy);
	}

	private byte[] cacheMicrodescs() {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		ArrayList<RouterMicrodesc> microdescs = microdescConsensus.getMicrodescs();
		stream.writeBytes(ByteBuffer.allocate(4).putInt(microdescs.size()).array());
		for (RouterMicrodesc microdesc : microdescs) {
			stream.writeBytes(cacheMicrodesc(microdesc));
		}

		return stream.toByteArray();
	}

	private static ArrayList<RouterMicrodesc> parseCachedMicrodescs(byte[] cachedMicrodescs) {
		ArrayList<RouterMicrodesc> routerMicrodescs = new ArrayList<>();
		ByteBuffer buffer = ByteBuffer.wrap(cachedMicrodescs);
		
		int microdescs = buffer.getInt();
		for (int i = 0; i < microdescs; i++) {
			routerMicrodescs.add(parseMicrodesc(buffer));
		}

		return routerMicrodescs;
	}

	private static byte[] serialiseDirectoryKeys(DirectoryKeys directoryKeys) {
		DirectoryKeyNetDoc[] directoryKeyNetDocs = directoryKeys.getDirectoryKeyNetDocs();
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		stream.write(directoryKeyNetDocs.length);
		for (DirectoryKeyNetDoc directoryKeyNetDoc : directoryKeyNetDocs) {
			byte[] signingKey = directoryKeyNetDoc.getDirectorySigningKey();
			byte[] fingerprint = directoryKeyNetDoc.getFingerprint();
			long published = directoryKeyNetDoc.getPublished();
			long expires = directoryKeyNetDoc.getExpires();
			stream.writeBytes(ByteBuffer.allocate(2).putShort((short) signingKey.length).array());
			stream.writeBytes(signingKey);
			stream.writeBytes(fingerprint);
			stream.writeBytes(ByteBuffer.allocate(8).putLong(published).array());
			stream.writeBytes(ByteBuffer.allocate(8).putLong(expires).array());
		}
		return stream.toByteArray();
	}

	private static DirectoryKeys parseCachedDirectoryKeys(byte[] cachedDirectoryKeys) {
		ByteBuffer buffer = ByteBuffer.wrap(cachedDirectoryKeys);
		DirectoryKeyNetDoc[] authorityKeyNetDocs = new DirectoryKeyNetDoc[buffer.get()];
		for (int i = 0; i < authorityKeyNetDocs.length; i++) {
			byte[] signingKey = new byte[buffer.getShort()];
			buffer.get(signingKey);
			byte[] fingerprint = new byte[20];
			buffer.get(fingerprint);
			long published = buffer.getLong();
			long expires = buffer.getLong();
			authorityKeyNetDocs[i] = new DirectoryKeyNetDoc(signingKey, fingerprint, published, expires);
		}
		return new DirectoryKeys(authorityKeyNetDocs);
	}

	public void cacheClientData(String path) {
		byte[] microdescs = cacheMicrodescs();
		HashMap<String, Integer> params = microdescConsensus.getParams();
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		stream.writeBytes(ByteBuffer.allocate(2).putShort((short) params.size()).array());
		for (String key : params.keySet()) {
			ByteBuffer buffer = ByteBuffer.allocate(2 + key.length() + 4);
			buffer.putShort((short) key.length());
			buffer.put(key.getBytes());
			buffer.putInt(params.get(key));
			stream.writeBytes(buffer.array());
		}
		byte[] parameters = stream.toByteArray();
        ByteBuffer vanguards = ByteBuffer.allocate(6 * (32 + 8));
        for (Guard.GuardInfo guard : vanguardsLite.getGuardSystem().getPrimary()) {
            vanguards.put(Base64.getDecoder().decode(guard.guardMicrodesc().getMicrodescHash()));
            vanguards.putLong(0);
        }
        for (VanguardsLayer.Vanguard vanguard : vanguardsLite.getSecondLayer().getVanguards()) {
            vanguards.put(Base64.getDecoder().decode(vanguard.getRouterMicrodesc().getMicrodescHash()));
            vanguards.putLong(vanguard.getRotate());
        }

		byte[] authorityKeysBytes = serialiseDirectoryKeys(authorityKeys);

		ByteBuffer buffer = ByteBuffer.allocate( 32 + 32 + parameters.length + 4 + microdescs.length + vanguards.capacity() + 4 + authorityKeysBytes.length);
		buffer.put(microdescConsensus.getCurrentSRV());
		buffer.put(microdescConsensus.getPreviousSRV());
		buffer.put(parameters);
		buffer.putInt(microdescs.length);
		buffer.put(microdescs);
		buffer.put(vanguards.array());
		buffer.putInt(authorityKeysBytes.length);
		buffer.put(authorityKeysBytes);

		try {
			DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(new FileOutputStream(path));
			deflaterOutputStream.write(buffer.array());
			deflaterOutputStream.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	private static MicrodescConsensus parseCachedClientData(ByteBuffer buffer) {
		byte[] currentSRV = new byte[32];
		byte[] previousSRV = new byte[32];
		buffer.get(currentSRV);
		buffer.get(previousSRV);
		short parameters = buffer.getShort();
		HashMap<String, Integer> params = new HashMap<>();
		for (int i = 0; i < parameters; i++) {
			byte[] key = new byte[buffer.getShort()];
			buffer.get(key);
			int value = buffer.getInt();
			params.put(new String(key), value);
		}
		byte[] microdescs = new byte[buffer.getInt()];
		buffer.get(microdescs);
		ArrayList<RouterMicrodesc> routerMicrodescs = parseCachedMicrodescs(microdescs);
		return new MicrodescConsensus(previousSRV, currentSRV, params, routerMicrodescs);
	}

	private boolean readyFromFile(String cachedDataPath) {
		if (!Files.exists(Path.of(cachedDataPath))) return false;
		byte[] data;
		try {
			InflaterInputStream inflaterInputStream = new InflaterInputStream(new FileInputStream(cachedDataPath));
			data = inflaterInputStream.readAllBytes();
			inflaterInputStream.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		ByteBuffer buffer = ByteBuffer.wrap(data);
		this.microdescConsensus = parseCachedClientData(buffer);
		byte[] vanguards = new byte[6 * (32 + 8)];
        buffer.get(vanguards);
		byte[] authorityKeysBytes = new byte[buffer.getInt()];
		buffer.get(authorityKeysBytes);
		authorityKeys = parseCachedDirectoryKeys(authorityKeysBytes);

        ByteBuffer vanguardsBuffer = ByteBuffer.wrap(vanguards);
        vanguardsLite = new VanguardsLite(microdescConsensus);
        ArrayList<RouterMicrodesc> primaryGuards = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            byte[] microdescHash = new byte[32];
            vanguardsBuffer.get(microdescHash);
            long rotate = vanguardsBuffer.getLong();
            RouterMicrodesc routerMicrodesc = microdescConsensus.getMicrodescs().stream().filter(microdesc -> Arrays.equals(Base64.getDecoder().decode(microdesc.getMicrodescHash()), microdescHash)).findFirst().orElse(null);
            primaryGuards.add(routerMicrodesc);
        }
        vanguardsLite.getGuardSystem().setPrimary(primaryGuards);
        for (int i = 0; i < 4; i++) {
            byte[] microdescHash = new byte[32];
            vanguardsBuffer.get(microdescHash);
            long rotate = vanguardsBuffer.getLong();
            RouterMicrodesc routerMicrodesc = microdescConsensus.getMicrodescs().stream().filter(microdesc -> Arrays.equals(Base64.getDecoder().decode(microdesc.getMicrodescHash()), microdescHash)).findFirst().orElse(null);
            if (routerMicrodesc != null)
                vanguardsLite.getSecondLayer().setVanguard(i, new VanguardsLayer.Vanguard(routerMicrodesc, rotate));
            else vanguardsLite.getSecondLayer().setVanguard(i, null);
        }

        vanguardsLite.fixAll();

		return true;
	}

	public void initialise(String cachedDataPath, Directory.Authorities directoryAuthority) {
		// Create a directory from it.
		Directory directory = new Directory(directoryAuthority.getIpv4(), directoryAuthority.getORPort());
		// Initialise.
		initialise(cachedDataPath, directory);
	}

	public void initialise(String cachedDataPath, Directory directory) {
		readyFromFile(cachedDataPath);
		if (authorityKeys != null && !authorityKeys.allValid())
			authorityKeys = null;
		microdescConsensus = null;
		initialise(directory);
	}

	public void initialise(Directory.Authorities directoryAuthority) {
		// Create a directory from it.
		Directory directory = new Directory(directoryAuthority.getIpv4(), directoryAuthority.getORPort());
		// Initialise.
		initialise(directory);
	}

	public void initialise(Directory directory) {
		// Prepare a circuit.
		if (!directory.prepareCircuit()) {
			clientState = FAILED_INIT_DIRECTORY_CONNECT;
			return;
		}

		// Fetch authority keys.
		if (authorityKeys == null)
			authorityKeys = directory.fetchAuthorityKeys();
		// Fetch microdescriptor consensus.
		if ((microdescConsensus = directory.fetchMicrodescConsensus(authorityKeys)) == null) {
			clientState = FAILED_MICRODESC_CONSENSUS_FETCH;
			return;
		}
		// Fetch all microdescriptors.
		if (!directory.fetchMicrodescriptors(microdescConsensus)) {
			clientState = FAILED_MICRODESCS_FETCH;
			return;
		}
		// Initialise the vanguards mesh.
        vanguardsLite = new VanguardsLite(microdescConsensus);

		clientState = OK;
	}

	private void ready() {
		clientState = OK;
	}

	public void initialiseCached(String cachedDataPath) {
		readyFromFile(cachedDataPath);
		ready();
	}

	// This function does nothing at the moment, but I'm hoping to replace it in the future with something that would make sure that all connections to the same IP are made on the same circuit.
	private String uniqueDestId(String destination) {
		return destination;
	}

	private Circuit createCircuit(int exitPort) {
        Guard.GuardInfo guardInfo = vanguardsLite.getEntryGuard();
		boolean exitCircuit = exitPort != -1;
		if (!guardInfo.guard().isConnected()) return null;
		Circuit circuit = new Circuit(random.nextInt(), guardInfo.guard());
		if (!circuit.create2(guardInfo.guardMicrodesc(), Handshakes.NTORv3))
			return null;
		List<RouterMicrodesc> fastNodes = new ArrayList<>(microdescConsensus.getAllWithFlags(RouterMicrodesc.Flags.FAST));
		RouterMicrodesc middleNode = null;
		while (middleNode == null) {
			middleNode = fastNodes.get(random.nextInt(fastNodes.size()));
			if (!circuit.extend2(middleNode))
				middleNode = null;
		}
		fastNodes.remove(middleNode);
		if (exitCircuit) {
			fastNodes = MicrodescConsensus.getAllWithoutFlag(MicrodescConsensus.getAllWithFlags(fastNodes, RouterMicrodesc.Flags.EXIT), RouterMicrodesc.Flags.BAD_EXIT);
			fastNodes = MicrodescConsensus.getAllWithExitPolicy(fastNodes, exitPort);
		}
		RouterMicrodesc lastNode = null;
		while (lastNode == null) {
			lastNode = fastNodes.get(random.nextInt(fastNodes.size()));
			if (!circuit.extend2(lastNode))
				lastNode = null;
		}
		return circuit;
	}

	public ConnectionInfo connect(String host, int port) {
		if (clientState != OK)
			throw new Error("Tried to connect without initialising first.");
		Circuit circuit = null;
		String uniqueId = uniqueDestId(host);

		if (circuitHashmap.containsKey(uniqueId))
			circuit = circuitHashmap.get(uniqueId);
		else {
            Guard.GuardInfo guardInfo = vanguardsLite.getEntryGuard();
			if (!guardInfo.guard().isConnected()) return null;
			for (int i = 0; i < 3 && circuit == null; i++)
				circuit = createCircuit(port);
			if (circuit == null)
				return null;
			circuitHashmap.put(uniqueId, circuit);
		}

		short streamId = (short) random.nextInt();
		byte status = (byte) circuit.openStream(streamId, host, port);
		if (status != Circuit.STREAM_SUCCESSFUL)
			return new ConnectionInfo(null, status);

		return new ConnectionInfo(new ConnectionIO(circuit, streamId), status);
	}

	public ConnectionInfo connectHS(String onionAddress, int port) {
		HiddenService hiddenService = new HiddenService(microdescConsensus, onionAddress);
		RouterMicrodesc[] possibleFetchDirectories = hiddenService.possibleFetchDirectories().toArray(new RouterMicrodesc[0]);
		Circuit circuit = null;
		for (int i = 0; i < 3 && circuit == null; i++)
			circuit = createCircuit(-1);
		if (circuit == null)
			return null;
		HSDirectory hsDirectory = new HSDirectory(microdescConsensus, possibleFetchDirectories[random.nextInt(possibleFetchDirectories.length)], circuit);
		if (!hsDirectory.extendToDirectory())
			return null;
		HiddenServiceDescriptor hsDescriptor = hsDirectory.fetchHSDescriptor(hiddenService);
		circuit.destroy(false);
		Circuit rendezvousCircuit = createCircuit(-1);
		for (int i = 0; i < 3 && rendezvousCircuit == null; i++)
			rendezvousCircuit = createCircuit(-1);
		if (rendezvousCircuit == null)
			return null;
		List<RouterMicrodesc> possibleRendezvousPoints = microdescConsensus.getAllWithFlags(RouterMicrodesc.Flags.FAST);
		RouterMicrodesc rendezvousPoint = possibleRendezvousPoints.get(random.nextInt(possibleRendezvousPoints.size()));
		if (!rendezvousCircuit.extend2(rendezvousPoint))
			return null;
		byte[] rendezvousCookie = rendezvousCircuit.establishRendezvous();
		if (rendezvousCookie == null)
			return null;
		List<IntroductionPoint> introductionPoints = hsDescriptor.getIntroductionPoints();

		Circuit introductionCircuit = null;

		IntroductionPoint introductionPoint = null;

		for (int i = 0; i < 3 && introductionCircuit == null; i++) {
			introductionPoint = introductionPoints.get(random.nextInt(introductionPoints.size()));
			introductionCircuit = createCircuit(-1);
		}
		if (introductionCircuit == null)
			return null;

		if (!introductionCircuit.extend2(introductionPoint))
			return null;
		IntroduceAckStatus introductionStatus = introductionCircuit.introduce1(introductionPoint, rendezvousPoint, rendezvousCookie, hiddenService);
		introductionCircuit.destroy(false);
		if (!rendezvousCircuit.rendezvous(introductionStatus.getKeyPair(), introductionPoint))
			return null;

		short streamId = (short) random.nextInt();
		byte status = (byte) rendezvousCircuit.openHSStream(streamId, port);
		if (status != Circuit.STREAM_SUCCESSFUL)
			return new ConnectionInfo(null, status);

		return new ConnectionInfo(new ConnectionIO(rendezvousCircuit, streamId), status);
	}

	public byte getClientState() {
		return clientState;
	}

}
