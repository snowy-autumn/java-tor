package snowy.autumn.tor.client;

import snowy.autumn.tor.cell.cells.relay.commands.IntroduceAckCommand;
import snowy.autumn.tor.directory.Directory;
import snowy.autumn.tor.directory.DirectoryKeys;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.hs.HiddenServiceDescriptor;
import snowy.autumn.tor.hs.IntroductionPoint;
import snowy.autumn.tor.vanguards.VanguardsLite;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class TorClient {

    public static class ClientState {
        public DirectoryKeys authorityKeys;
        public MicrodescConsensus microdescConsensus;
        public VanguardsLite vanguardsLite;
        public CircuitManager circuitManager;
        public Random random;

        public ClientState(DirectoryKeys authorityKeys, MicrodescConsensus microdescConsensus, VanguardsLite vanguardsLite) {
            this();
            this.authorityKeys = authorityKeys;
            this.microdescConsensus = microdescConsensus;
            this.vanguardsLite = vanguardsLite;
        }

        public ClientState() {
            this.random = new Random();
            this.circuitManager = new CircuitManager(this);
        }

    }

    Logger logger;
    ClientCacheManager cacheManager;
    ClientState clientState;
    boolean bootstrapped;

    public TorClient(String cacheFilePath, boolean debug) {
        logger = new Logger(debug);
        cacheManager = new ClientCacheManager(cacheFilePath == null ? null : Path.of(cacheFilePath), logger);
        clientState = new ClientState();
    }

    public TorClient(String cacheFilePath) {
        this(cacheFilePath, false);
    }

    private void handleAuthorityKeys(Directory directory) {
        if (clientState.authorityKeys == null)
            logger.info("No authority keys found. Fetching..");
        else if (!clientState.authorityKeys.allValid())
            logger.info("One or more authority keys have expired or are invalid. Refetching..");
        else return;
        clientState.authorityKeys = directory.fetchAuthorityKeys();
        logger.info("Authority keys fetched.");
    }

    private boolean fetchMicrodescConsensus(Directory directory) {
        // Prepare the directory circuit.
        if (!directory.prepareCircuit()) {
            logger.error("Failed to connect to directory " + directory + ".");
            return false;
        }
        logger.info("Connected to directory " + directory + ".");

        // Handle the authority keys to make sure we've got everything we need before we fetch a consensus.
        handleAuthorityKeys(directory);

        // Attempt to fetch a microdesc consensus.
        logger.info("Attempting to fetch a microdesc consensus from " + directory + ".");
        clientState.microdescConsensus = directory.fetchMicrodescConsensus(clientState.authorityKeys);
        if (clientState.microdescConsensus == null) {
            logger.error("Failed to fetch microdesc consensus.");
            return false;
        }
        logger.info("Fetched microdesc consensus.");

        // Attempt to fetch all microdescriptors that are listed on the microdesc consensus.
        logger.info("Attempting to fetch all microdescriptors from directory " + directory + ".");
        if (!directory.fetchMicrodescriptors(clientState.microdescConsensus)) {
            logger.error("Failed to fetch all microdescriptors.");
            return false;
        }

        directory.destroyCircuit();

        logger.info("Microdescriptors fetched successfully.");
        return true;
    }

    public boolean initClient() {
        // Create an arraylist that contains all known authorities. Should also add fallbacks in the future.
        ArrayList<Directory.Authorities> authorities = new ArrayList<>(Arrays.stream(Directory.Authorities.values()).toList());
        // Make at most 3 attempts to initialise the client;
        for (int i = 0; i < 3; i++) {
            // Pick a random authority to use as the directory for bootstrapping.
            Directory.Authorities authority = authorities.get(clientState.random.nextInt(authorities.size()));
            // Create a Directory object for the authority.
            Directory directory = new Directory(authority.getIpv4(), authority.getORPort());
            // Attempt to initialise the client with the authority.
            initClient(directory);
            // If we've managed to bootstrap, we can break out of the loop.
            if (bootstrapped)
                break;
            // If not, log the issue.
            logger.info("Failed to initialise with directory " + directory + ".");
        }
        return bootstrapped;
    }

    public void initClient(Directory directory) {
        // Initialise the cache manager.
        byte cacheManagerStatus = cacheManager.init();
        if (cacheManagerStatus == ClientCacheManager.INIT_FAILED) return;
        else if (cacheManagerStatus == ClientCacheManager.CACHE_FOUND) {
            // Attempt to load the client's data from the cache file.
            // If the client was not able to load its data from the cache file, then we should terminate the client's init process.
            if (!cacheManager.loadClientData(clientState)) {
                logger.error("Failed to load cached client data. You could try deleting the file and let the client create a new one.");
                return;
            }
            // If the consensus is no longer valid, then we need to fetch a new one.
            if (!clientState.microdescConsensus.isValid()) {
                logger.info("Consensus is no longer valid. Attempting to refetch.");
                List<RouterMicrodesc> potentialDirectories = clientState.microdescConsensus.getAllWithFlags(RouterMicrodesc.Flags.V2DIR);
                boolean fetched = false;
                for (int i = 0; i < 3; i++) {
                    RouterMicrodesc dirMicrodesc = potentialDirectories.get(clientState.random.nextInt(potentialDirectories.size()));
                    logger.info("Attempting to build a circuit to directory " + dirMicrodesc.getHost() + ":" + dirMicrodesc.getPort() + ".");
                    Directory directoryPreference = clientState.circuitManager.createDirectoryCircuit(dirMicrodesc);
                    if (!(fetched = fetchMicrodescConsensus(directoryPreference)))
                        logger.info("Failed to fetch a microdesc consensus from " + directoryPreference + ". Retrying.");
                    else break;
                }
                if (!fetched) {
                    logger.info("Failed to fetch from random directories. Defaulting to fallback " + directory + ".");
                    fetched = fetchMicrodescConsensus(directory);
                }
                if (!fetched) {
                    logger.error("Failed to fetch microdesc consensus. Terminating client.");
                    return;
                }
                // Storing the new microdesc consensus.
                cacheManager.storeClientData(clientState.authorityKeys, clientState.microdescConsensus, clientState.vanguardsLite);
                // Reloading all client data.
                if (!cacheManager.loadClientData(clientState)) {
                    logger.error("Failed to load the new microdesc consensus from file. Try rerunning the client.");
                    return;
                }
            }
        }
        else if (cacheManagerStatus == ClientCacheManager.NEW_CACHE || cacheManagerStatus == ClientCacheManager.EPHEMERAL_MODE) {
            // Attempt to fetch a microdesc consensus.
            if (!fetchMicrodescConsensus(directory))
                return;
            // Initialise the vanguards-lite system (that includes the regular guards system).
            logger.info("Initialising Vanguards and Entry Guards.");
            clientState.vanguardsLite = new VanguardsLite(clientState.microdescConsensus);
            logger.info("Vanguards Lite initialised.");

            cacheManager.storeClientData(clientState.authorityKeys, clientState.microdescConsensus, clientState.vanguardsLite);
        }

        bootstrapped = true;
        logger.info("Client::Ready.");
    }

    public ConnectionInfo connect(String host, int port) {
        if (!bootstrapped) throw new RuntimeException("Client must be initialised before building circuits.");
        logger.info("Attempting to connect to " + host + ':' + port + '.');
        int circuitId = clientState.circuitManager.createDefaultCircuit(port);
        logger.info("Created a new circuit through the tor network, circuitId: " + circuitId + '.');
        ConnectionInfo connectionInfo = clientState.circuitManager.connectWithCircuit(circuitId, host, port);
        if (connectionInfo == null) logger.info("Failed to establish a connection to " + host + ':' + port + '.');
        else logger.info("Connected to " + host + ':' + port + '.');
        return connectionInfo;
    }

    public ConnectionInfo connectHS(String onionAddress, int port) {
        if (!bootstrapped) throw new RuntimeException("Client must be initialised before building circuits.");
        logger.info("Attempting to fetch the hidden service descriptor for " + onionAddress + '.');
        HiddenService hiddenService = new HiddenService(clientState.microdescConsensus, onionAddress);
        HiddenServiceDescriptor hiddenServiceDescriptor = null;
        for (int i = 0; i < 3; i++) {
            if ((hiddenServiceDescriptor = clientState.circuitManager.fetchHSDescriptor(hiddenService)) != null) break;
        }
        if (hiddenServiceDescriptor == null) return null;

        ArrayList<IntroductionPoint> introductionPoints = hiddenServiceDescriptor.getIntroductionPoints();
        IntroductionPoint introductionPoint = introductionPoints.get(clientState.random.nextInt(introductionPoints.size()));

        CircuitManager.RendezvousInfo rendezvousInfo = clientState.circuitManager.establishRendezvous();
        logger.info("Created a new rendezvous circuit through the tor network, circuitId: " + rendezvousInfo.circuitId() + '.');
        logger.info("Established rendezvous on circuit " + rendezvousInfo.circuitId() + '.');
        IntroduceAckCommand.IntroduceAckStatus introduceAckStatus = clientState.circuitManager.introduce(hiddenService, introductionPoint, rendezvousInfo);
        // If introduceAckStatus is null, then we've failed to do an introduction.
        if (introduceAckStatus == null) logger.info("Failed to build an introduction circuit.");
        else logger.info("Introduction status: " + introduceAckStatus);

        if (introduceAckStatus != IntroduceAckCommand.IntroduceAckStatus.SUCCESS) {
            logger.info("Failed to finish introduction with hidden service.");
            clientState.circuitManager.tearCircuit(rendezvousInfo.circuitId());
            return null;
        }
        if (!clientState.circuitManager.finishRendezvous(rendezvousInfo.circuitId(), introductionPoint, introduceAckStatus.getKeyPair())) {
            logger.info("Failed to finish rendezvous with hidden service.");
            clientState.circuitManager.tearCircuit(rendezvousInfo.circuitId());
            return null;
        }
        ConnectionInfo connectionInfo = clientState.circuitManager.connectHSWithCircuit(rendezvousInfo.circuitId(), port);
        if (connectionInfo == null) logger.info("Failed to establish a connection to " + onionAddress + ':' + port + '.');
        else logger.info("Connected to " + onionAddress + ':' + port + '.');
        return connectionInfo;
    }

    public void shutdown() {
        logger.info("Client::Shutdown");
        clientState.vanguardsLite.getGuardSystem().getPrimary().forEach(guard -> guard.guard().terminate());
        bootstrapped = false;
    }

}
