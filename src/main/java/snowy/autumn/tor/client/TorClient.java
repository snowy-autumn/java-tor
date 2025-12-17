package snowy.autumn.tor.client;

import snowy.autumn.tor.cell.cells.relay.commands.IntroduceAckCommand;
import snowy.autumn.tor.directory.Directory;
import snowy.autumn.tor.directory.DirectoryKeys;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.hs.HiddenService;
import snowy.autumn.tor.hs.HiddenServiceDescriptor;
import snowy.autumn.tor.hs.IntroductionPoint;
import snowy.autumn.tor.vanguards.VanguardsLite;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Random;

public class TorClient {

    public static class ClientState {
        public DirectoryKeys authorityKeys;
        public MicrodescConsensus microdescConsensus;
        public VanguardsLite vanguardsLite;
        public CircuitManager circuitManager;

        public ClientState(DirectoryKeys authorityKeys, MicrodescConsensus microdescConsensus, VanguardsLite vanguardsLite) {
            this();
            this.authorityKeys = authorityKeys;
            this.microdescConsensus = microdescConsensus;
            this.vanguardsLite = vanguardsLite;
        }

        public ClientState() {
            this.circuitManager = new CircuitManager(this);
        }

    }

    Logger logger;
    ClientCacheManager cacheManager;

    ClientState clientState;

    public TorClient(String cacheFilePath, boolean debug) {
        logger = new Logger(debug);
        cacheManager = new ClientCacheManager(Path.of(cacheFilePath), logger);
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

    public void initClient(Directory directory) {
        // Initialise the cache manager.
        byte cacheManagerStatus = cacheManager.init();
        if (cacheManagerStatus == ClientCacheManager.INIT_FAILED) return;
        else if (cacheManagerStatus == ClientCacheManager.CACHE_FOUND) {
            // Attempt to load the client's data from the cache file.
            // If the client was not able to load its data from the cache file, then we should terminate the client's init process.
            if (!cacheManager.loadClientData(clientState))
                return;
        }
        else if (cacheManagerStatus == ClientCacheManager.NEW_CACHE || cacheManagerStatus == ClientCacheManager.EPHEMERAL_MODE) {
            // Prepare the directory circuit.
            if (!directory.prepareCircuit()) {
                logger.error("Failed to connect to directory " + directory + ".");
                return;
            }
            logger.info("Connected to directory " + directory + ".");

            // Handle the authority keys to make sure we've got everything we need before we fetch a consensus.
            handleAuthorityKeys(directory);

            // Attempt to fetch a microdesc consensus.
            logger.info("Attempting to fetch a microdesc consensus from " + directory + ".");
            clientState.microdescConsensus = directory.fetchMicrodescConsensus(clientState.authorityKeys);
            if (clientState.microdescConsensus == null) {
                logger.error("Failed to fetch microdesc consensus.");
                return;
            }
            logger.info("Fetched microdesc consensus.");

            // Attempt to fetch all microdescriptors that are listed on the microdesc consensus.
            logger.info("Attempting to fetch all microdescriptors from directory " + directory + ".");
            if (!directory.fetchMicrodescriptors(clientState.microdescConsensus)) {
                logger.error("Failed to fetch all microdescriptors.");
                return;
            }
            logger.info("Microdescriptors fetched successfully.");

            // Initialise the vanguards-lite system (that includes the regular guards system).
            logger.info("Initialising Vanguards and Entry Guards.");
            clientState.vanguardsLite = new VanguardsLite(clientState.microdescConsensus);
            logger.info("Vanguards Lite initialised.");

            cacheManager.storeClientData(clientState.authorityKeys, clientState.microdescConsensus, clientState.vanguardsLite);
        }

        logger.info("Client::Ready.");
    }

    public ConnectionInfo connect(String host, int port) {
        logger.info("Attempting to connect to " + host + ':' + port + '.');
        int circuitId = clientState.circuitManager.createDefaultCircuit(port);
        logger.info("Created a new circuit through the tor network, circuitId: " + circuitId + '.');
        ConnectionInfo connectionInfo = clientState.circuitManager.connectWithCircuit(circuitId, host, port);
        if (connectionInfo == null) logger.info("Failed to establish a connection to " + host + ':' + port + '.');
        else logger.info("Connected to " + host + ':' + port + '.');
        return connectionInfo;
    }

    public ConnectionInfo connectHS(String onionAddress, int port) {
        logger.info("Attempting to fetch the hidden service descriptor for " + onionAddress + '.');
        HiddenService hiddenService = new HiddenService(clientState.microdescConsensus, onionAddress);
        HiddenServiceDescriptor hiddenServiceDescriptor = clientState.circuitManager.fetchHSDescriptor(hiddenService);

        ArrayList<IntroductionPoint> introductionPoints = hiddenServiceDescriptor.getIntroductionPoints();
        IntroductionPoint introductionPoint = introductionPoints.get(new Random().nextInt(introductionPoints.size()));

        CircuitManager.RendezvousInfo rendezvousInfo = clientState.circuitManager.establishRendezvous();
        logger.info("Created a new rendezvous circuit through the tor network, circuitId: " + rendezvousInfo.circuitId() + '.');
        logger.info("Established rendezvous on circuit " + rendezvousInfo.circuitId() + '.');
        IntroduceAckCommand.IntroduceAckStatus introduceAckStatus = clientState.circuitManager.introduce(hiddenService, introductionPoint, rendezvousInfo);
        logger.info("Introduction status: " + introduceAckStatus);
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

}
