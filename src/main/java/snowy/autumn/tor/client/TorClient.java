package snowy.autumn.tor.client;

import snowy.autumn.tor.cell.cells.relay.commands.IntroduceAckCommand.IntroduceAckStatus;
import snowy.autumn.tor.circuit.Circuit;
import snowy.autumn.tor.directory.Directories;
import snowy.autumn.tor.directory.Directory;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.hs.HSDirectory;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.hs.HiddenServiceDescriptor;
import snowy.autumn.tor.hs.IntroductionPoint;
import snowy.autumn.tor.relay.Guard;
import snowy.autumn.tor.relay.Handshakes;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
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

	MicrodescConsensus microdescConsensus;
	RouterMicrodesc guardMicrodesc = null;
	Guard guard = null;

	HashMap<String, Circuit> circuitHashmap = new HashMap<>();
	ReentrantLock circuitLock = new ReentrantLock();

	Random random = new Random();

	byte clientState = PRE_INIT;

	public TorClient() {

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
		byte[] guardMicrodescBytes = cacheMicrodesc(guardMicrodesc);
		ByteBuffer buffer = ByteBuffer.allocate(microdescs.length + 32 + 32 + parameters.length + 4 + guardMicrodescBytes.length);
		buffer.put(microdescConsensus.getCurrentSRV());
		buffer.put(microdescConsensus.getPreviousSRV());
		buffer.put(parameters);
		buffer.putInt(microdescs.length);
		buffer.put(microdescs);
		buffer.put(guardMicrodescBytes);
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

	public void initialise(Directories.Authorities directoryAuthority) {
		// Create a directory from it.
		Directory directory = new Directory(directoryAuthority.getIpv4(), directoryAuthority.getORPort());
		// Prepare a circuit.
		if (!directory.prepareCircuit()) {
			clientState = FAILED_INIT_DIRECTORY_CONNECT;
			return;
		}
		// Fetch microdescriptor consensus.
		if ((microdescConsensus = directory.fetchMicrodescConsensus()) == null) {
			clientState = FAILED_MICRODESC_CONSENSUS_FETCH;
			return;
		}
		// Fetch all microdescriptors.
		if (!directory.fetchMicrodescriptors(microdescConsensus)) {
			clientState = FAILED_MICRODESCS_FETCH;
			return;
		}
		// Pick a guard and test it.
		List<RouterMicrodesc> guardNodes = microdescConsensus.getAllWithFlag(RouterMicrodesc.Flags.GUARD);
		Random random = new Random();
		for (int i = 0; i < 3; i++) {
			RouterMicrodesc microdesc = guardNodes.get(random.nextInt(guardNodes.size()));
			Guard guard = new Guard(microdesc);
			if (!guard.connect()) continue;
			if (!guard.generalTorHandshake()) continue;
			guard.startCellListener();
			this.guard = guard;
			guardMicrodesc = microdesc;
		}
		// If no working guard was found, make sure the client state gets updated.
		if (guardMicrodesc == null) {
			clientState = NO_VALID_GUARD;
			return;
		}

		clientState = OK;
	}

	public void initialiseCached(String microdescConsensusPath) {
		byte[] data;
		try {
			InflaterInputStream inflaterInputStream = new InflaterInputStream(new FileInputStream(microdescConsensusPath));
			data = inflaterInputStream.readAllBytes();
			inflaterInputStream.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		ByteBuffer buffer = ByteBuffer.wrap(data);
		this.microdescConsensus = parseCachedClientData(buffer);
		guardMicrodesc = parseMicrodesc(buffer);
		this.guard = new Guard(guardMicrodesc);
		if (!guard.connect())
			guardMicrodesc = null;
		else if (!guard.generalTorHandshake())
			guardMicrodesc = null;
		guard.startCellListener();

		if (guardMicrodesc == null) {
			clientState = NO_VALID_GUARD;
			return;
		}
		
		clientState = OK;
	}

	// This function does nothing at the moment, but I'm hoping to replace it in the future with something that would make sure that all connections to the same IP are made on the same circuit.
	private String uniqueDestId(String destination) {
		return destination;
	}

	private Circuit createCircuit(int exitPort) {
		boolean exitCircuit = exitPort != -1;
		if (!guard.isConnected()) return null;
		Circuit circuit = new Circuit(random.nextInt(), guard);
		if (!circuit.create2(guardMicrodesc, Handshakes.NTORv3))
			return null;
		List<RouterMicrodesc> fastNodes = new ArrayList<>(microdescConsensus.getAllWithFlag(RouterMicrodesc.Flags.FAST));
		RouterMicrodesc middleNode = null;
		while (middleNode == null) {
			middleNode = fastNodes.get(random.nextInt(fastNodes.size()));
			if (!circuit.extend2(middleNode))
				middleNode = null;
		}
		fastNodes.remove(middleNode);
		if (exitCircuit) {
			fastNodes = MicrodescConsensus.getAllWithoutFlag(MicrodescConsensus.getAllWithFlag(fastNodes, RouterMicrodesc.Flags.EXIT), RouterMicrodesc.Flags.BAD_EXIT);
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
			if (!guard.isConnected()) return null;
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
		List<RouterMicrodesc> possibleRendezvousPoints = microdescConsensus.getAllWithFlag(RouterMicrodesc.Flags.FAST);
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
