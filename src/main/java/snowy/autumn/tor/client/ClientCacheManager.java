package snowy.autumn.tor.client;

import snowy.autumn.tor.directory.DirectoryKeys;
import snowy.autumn.tor.directory.documents.DirectoryKeyNetDoc;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;
import snowy.autumn.tor.vanguards.VanguardsLayer;
import snowy.autumn.tor.vanguards.VanguardsLite;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

public class ClientCacheManager {

    public final static byte EPHEMERAL_MODE = 0;
    public final static byte NEW_CACHE = 1;
    public final static byte CACHE_FOUND = 2;
    public final static byte INIT_FAILED = -1;

    private static class CacheFileOutputStream extends DeflaterOutputStream {

        public CacheFileOutputStream(Path path) throws FileNotFoundException {
            // Clear the cache file.
            super(new FileOutputStream(path.toFile(), false));

        }

        public void writeShortString(String value) throws IOException {
            writeShort((short) value.length());
            super.write(value.getBytes());
        }

        public void writeShort(short value) throws IOException {
            super.write(value >> 8);
            super.write(value & 0xFF);
        }

        public void writeInt(int value) throws IOException {
            super.write(ByteBuffer.allocate(4).putInt(value).array());
        }

        public void writeLong(long value) throws IOException {
            super.write(ByteBuffer.allocate(8).putLong(value).array());
        }
    }

    private static class CacheFileInputStream extends InflaterInputStream {

        public CacheFileInputStream(Path path) throws FileNotFoundException {
            super(new FileInputStream(path.toFile()));
        }

        public String readShortString() throws IOException {
            return new String(readNBytes(readShort()));
        }

        public short readShort() throws IOException {
            return (short) ((read() << 8) | read());
        }

        public int readUShort() throws IOException {
            return Short.toUnsignedInt((short) ((read() << 8) | read()));
        }

        public int readInt() throws IOException {
            return ByteBuffer.wrap(readNBytes(4)).getInt();
        }

        public long readLong() throws IOException {
            return ByteBuffer.wrap(readNBytes(8)).getLong();
        }

    }

    Logger logger;
    Path cacheFilePath;

    public ClientCacheManager(Path cacheFilePath, Logger logger) {
        this.cacheFilePath = cacheFilePath;
        this.logger = logger;
    }

    public byte init() {
        // In case the given filepath is null, we don't want to use a cache.
        if (cacheFilePath == null) {
            logger.info("Client initialised in ephemeral mode. No cache file used.");
            return EPHEMERAL_MODE;
        }
        // If the given filepath exists, then we should attempt to load it.
        else if (Files.exists(cacheFilePath)) {
            logger.info("Cache file found.");
            return CACHE_FOUND;
        }
        // If the given filepath doesn't exist, then we should create a new one.
        else {
            logger.info("No cache file was found. Creating a new one..");
            try {
                Files.createFile(cacheFilePath);
                logger.info("Cache file created.");
                return NEW_CACHE;
            } catch (IOException e) {
                logger.error("Failed to create cache file " + cacheFilePath + ".");
                return INIT_FAILED;
            }
        }
    }

    private void storeRouterMicrodesc(RouterMicrodesc routerMicrodesc, CacheFileOutputStream outputStream) throws IOException {
        byte hasIpv6 = (byte) (routerMicrodesc.hasIpv6Address() ? 1 : 0);
        byte[] ipv4ExitPolicy = routerMicrodesc.getIpv4ExitPolicy() != null ? routerMicrodesc.getIpv4ExitPolicy().serialise() : null;
        // Store microdesc flags.
        outputStream.write(routerMicrodesc.getFlags());
        // Store ipv4 host and port.
        outputStream.write(routerMicrodesc.getIpv4Host());
        outputStream.writeShort((short) routerMicrodesc.getPort());
        // Store the router's rsa identity.
        outputStream.write(routerMicrodesc.getFingerprint());
        // Store the router's ed25519 identity.
        outputStream.write(routerMicrodesc.getEd25519Id());
        // Store the router's ntor onion key.
        outputStream.write(routerMicrodesc.getNtorOnionKey());
        // Store the microdesc hash.
        outputStream.write(Base64.getDecoder().decode(routerMicrodesc.getMicrodescHash()));
        // Store a boolean value indicating whether the router has an ipv6 address.
        outputStream.write(hasIpv6);
        // If it does, then store the ipv6 address and port of the router.
        if (hasIpv6 == 1) {
            try {
                // Attempt to serialise and store the ipv6 host of the router.
                outputStream.write(Inet6Address.getByName(routerMicrodesc.getIpv6host()).getAddress());
            }
            catch (UnknownHostException e) {
                throw new RuntimeException(e);
            }
            // Store ipv6 port of the router.
            outputStream.writeShort((short) routerMicrodesc.getIpv6port());
        }
        // Store the family of the router.
        outputStream.writeShort((short) routerMicrodesc.getFamily().length);
        for (byte[] router : routerMicrodesc.getFamily()) {
            // Each router in the family is represented by its rsa identity (fingerprint [20 bytes]).
            outputStream.write(router);
        }
        // Store a boolean value representing whether the router has a specific ipv4 exit policy.
        outputStream.write(ipv4ExitPolicy != null ? 1 : 0);
        // If it does, then store the exit policy.
        if (ipv4ExitPolicy != null) {
            outputStream.writeInt(ipv4ExitPolicy.length);
            outputStream.write(ipv4ExitPolicy);
        }
    }

    private RouterMicrodesc loadRouterMicrodesc(CacheFileInputStream inputStream) throws IOException {
        // Read the microdesc flags.
        byte flags = (byte) inputStream.read();
        // Read the ipv4 host and port.
        byte[] host = inputStream.readNBytes(4);
        short port = inputStream.readShort();
        // Read the relay's rsa identity.
        byte[] fingerprint = inputStream.readNBytes(20);
        // Read the relay's ed25519 identity.
        byte[] ed25519Id = inputStream.readNBytes(32);
        // Read the relay's ntor onion key.
        byte[] ntorOnionKey = inputStream.readNBytes(32);
        // Read the microdesc hash.
        byte[] microdescHash = inputStream.readNBytes(32);
        // Create variables to hold potential ipv6 address and port.
        byte[] ipv6host = null;
        short ipv6port = -1;
        // Read the value indicating whether the relay has an ipv6 address.
        boolean hasIpv6 = inputStream.read() == 1;
        // If it does, the read the relay's ipv6 address and port.
        if (hasIpv6) {
            // Read the ipv6 host.
            ipv6host = inputStream.readNBytes(16);
            // Read the ipv6 port.
            ipv6port = inputStream.readShort();
        }
        // Load the relay's family.
        // Read the relay's family size and initialise an empty family array.
        byte[][] family = new byte[inputStream.readShort()][];
        // Read in each relay in the family (by fingerprint [20 bytes]).
        for (int i = 0; i < family.length; i++) {
            family[i] = inputStream.readNBytes(20);
        }
        // Initialise a null variable to hold a potential ipv4 exit policy.
        RouterMicrodesc.ExitPolicy ipv4ExitPolicy = null;
        // Read the value indicating whether the router has a specific ipv4 exit policy.
        boolean hasIpv4ExitPolicy = inputStream.read() == 1;
        // If it does, then read the exit policy.
        if (hasIpv4ExitPolicy) {
            // Read the length of and the serialised ipv4 exit policy. Load the exit policy afterwards.
            ipv4ExitPolicy = RouterMicrodesc.ExitPolicy.load(inputStream.readNBytes(inputStream.readInt()));
        }
        // Finally, create a new RouterMicrodesc instance from the data read, and return it.
        return new RouterMicrodesc(flags, host, port, fingerprint, ed25519Id, ntorOnionKey, microdescHash, ipv6host, ipv6port, family, ipv4ExitPolicy);
    }

    public void storeClientData(DirectoryKeys authorityKeys, MicrodescConsensus microdescConsensus, VanguardsLite vanguardsLite) {
        try {
            // Create an output stream and clear the cache file.
            CacheFileOutputStream outputStream = new CacheFileOutputStream(cacheFilePath);
            // Serialise the authority keys.
            DirectoryKeyNetDoc[] directoryKeyNetDocs = authorityKeys.getDirectoryKeyNetDocs();
            // Store the number of directory key network documents.
            outputStream.write(directoryKeyNetDocs.length);
            for (DirectoryKeyNetDoc directoryKeyNetDoc : directoryKeyNetDocs) {
                byte[] signingKey = directoryKeyNetDoc.getDirectorySigningKey();
                // Store the length of the signing key (short).
                outputStream.writeShort((short) signingKey.length);
                // Store the signing key.
                outputStream.write(signingKey);
                // Store the fingerprint (20 bytes).
                outputStream.write(directoryKeyNetDoc.getFingerprint());
                // Store the published and expired values (long).
                outputStream.writeLong(directoryKeyNetDoc.getPublished());
                outputStream.writeLong(directoryKeyNetDoc.getExpires());
            }

            // Serialise the microdesc consensus.
            // Store the shared random values listed in the consensus.
            outputStream.write(microdescConsensus.getCurrentSRV());
            outputStream.write(microdescConsensus.getPreviousSRV());
            // Store the consensus parameters.
            HashMap<String, Integer> parameters = microdescConsensus.getParams();
            // Store the number of parameters (short).
            outputStream.writeShort((short) parameters.size());
            for (Map.Entry<String, Integer> entry : parameters.entrySet()) {
                // Store the parameter name.
                outputStream.writeShortString(entry.getKey());
                // Store the parameter value.
                outputStream.writeInt(entry.getValue());
            }
            // Store the number of microdescs in the consensus.
            ArrayList<RouterMicrodesc> routerMicrodescs = microdescConsensus.getMicrodescs();
            outputStream.writeInt(routerMicrodescs.size());
            // Store the microdescriptors.
            for (RouterMicrodesc routerMicrodesc : routerMicrodescs) {
                storeRouterMicrodesc(routerMicrodesc, outputStream);
            }

            // Serialise the VanguardsLite instance.
            // Serialise the guard system.
            GuardSystem guardSystem = vanguardsLite.getGuardSystem();
            // Store the number of sampled relays.
            outputStream.writeShort((short) guardSystem.getSampled().size());
            // Store the sampled relays' microdesc hashes.
            for (RouterMicrodesc sampled : guardSystem.getSampled()) {
                outputStream.write(Base64.getDecoder().decode(sampled.getMicrodescHash()));
            }
            // Store the number of filtered relays.
            outputStream.writeShort((short) guardSystem.getFiltered().size());
            // Store the filtered relays' microdesc hashes.
            for (RouterMicrodesc filtered : guardSystem.getFiltered()) {
                outputStream.write(Base64.getDecoder().decode(filtered.getMicrodescHash()));
            }
            // Store the number of primary guards.
            outputStream.writeShort((short) guardSystem.getPrimary().size());
            // Store the primary guards' microdesc hashes and lifetimes (long).
            for (Guard.GuardInfo primary : guardSystem.getPrimary()) {
                // Store the guard's microdesc hash.
                outputStream.write(Base64.getDecoder().decode(primary.guardMicrodesc().getMicrodescHash()));
                // Store the guard's lifetime (currently a constant 0 as guard lifetimes are not being accounted for at the moment).
                outputStream.writeLong(0);
            }
            // Serialise the vanguards.
            // Store the number of second layer vanguards.
            outputStream.writeShort((short) vanguardsLite.getSecondLayer().getVanguards().length);
            // Store the second layer vanguards.
            for (VanguardsLayer.Vanguard vanguard : vanguardsLite.getSecondLayer().getVanguards()) {
                // Store the vanguard's microdesc hash.
                outputStream.write(Base64.getDecoder().decode(vanguard.getRouterMicrodesc().getMicrodescHash()));
                // Store the vanguard's rotation time (long).
                outputStream.writeLong(vanguard.getRotate());
            }

            // Finally, close the cache file output stream.
            outputStream.close();
            logger.info("Client data written to cache file.");
        } catch (IOException e) {
            logger.error("Failed to write data to cache file.");
        }
    }

    public boolean loadClientData(TorClient.ClientState clientState) {
        try {
            // Create an input stream for the cache file.
            CacheFileInputStream inputStream = new CacheFileInputStream(cacheFilePath);
            // Load the authority keys.
            // Read the amount of stored directory key network documents and initialise an array of that size.
            DirectoryKeyNetDoc[] directoryKeyNetDocs = new DirectoryKeyNetDoc[inputStream.read()];
            for (int i = 0; i < directoryKeyNetDocs.length; i++) {
                // Read the length of and the signing key.
                byte[] signingKey = inputStream.readNBytes(inputStream.readShort());
                // Read the authority's rsa identity (fingerprint).
                byte[] fingerprint = inputStream.readNBytes(20);
                // Read the published and expired values (long).
                long published = inputStream.readLong();
                long expired = inputStream.readLong();
                // Store these values in a new DirectoryKeyNetDoc object.
                directoryKeyNetDocs[i] = new DirectoryKeyNetDoc(signingKey, fingerprint, published, expired);
            }
            // Store the authority keys in clientState.
            clientState.authorityKeys = new DirectoryKeys(directoryKeyNetDocs);

            // Load the microdesc consensus.
            // Read the shared random values.
            byte[] currentSRV = inputStream.readNBytes(32);
            byte[] previousSRV = inputStream.readNBytes(32);
            // Read the consensus parameters.
            // Read in the number of parameters stored.
            int parametersStored = inputStream.readShort();
            // Initialise a new hashmap with the initial capacity set to the number of parameters read.
            HashMap<String, Integer> parameters = new HashMap<>(parametersStored);
            for (int i = 0; i < parametersStored; i++) {
                // Read the parameter name.
                String key = inputStream.readShortString();
                // Read the parameter value.
                int value = inputStream.readInt();
                // Store the values as a pair in the hashmap.
                parameters.put(key, value);
            }
            // Read in the number of microdescriptors stored.
            int microdescriptors = inputStream.readInt();
            // Initialise an ArrayList to hold the stored microdescriptors with the initial capacity being the amount read.
            ArrayList<RouterMicrodesc> routerMicrodescs = new ArrayList<>(microdescriptors);
            // Load the cached microdescriptors.
            for (int i = 0; i < microdescriptors; i++) {
                routerMicrodescs.add(loadRouterMicrodesc(inputStream));
            }
            // Store the microdesc consensus data in clientState.
            clientState.microdescConsensus = new MicrodescConsensus(previousSRV, currentSRV, parameters, routerMicrodescs);

            // Load the serialised VanguardsLite instance.
            // Create a new VanguardsLite instance in clientState.
            clientState.vanguardsLite = new VanguardsLite(clientState.microdescConsensus);
            // Load the serialised guard system data.
            ArrayList<RouterMicrodesc> sampled = new ArrayList<>();
            // Read the number of sampled relays.
            int sampledRelays = inputStream.readUShort();
            for (int i = 0; i < sampledRelays; i++) {
                // Read the microdesc hash for the relay.
                byte[] microdescHash = inputStream.readNBytes(32);
                // Find the relay in the microdesc consensus.
                RouterMicrodesc sampledRelay = clientState.microdescConsensus.findWithHash(microdescHash);
                if (sampledRelay != null) sampled.add(sampledRelay);
                else {
                    // This should never happen, as the client does not currently update its consensus mid-run.
                    logger.error("Mismatched microdesc consensus and stored relay.");
                    return false;
                }
            }
            // Set the sampled relays for the client to the ones we just loaded.
            clientState.vanguardsLite.getGuardSystem().setSampled(sampled);
            ArrayList<RouterMicrodesc> filtered = new ArrayList<>();
            // Read the number of filtered relays.
            int filteredRelays = inputStream.readUShort();
            for (int i = 0; i < filteredRelays; i++) {
                // Read the microdesc hash for the relay.
                byte[] microdescHash = inputStream.readNBytes(32);
                // Find the relay in the microdesc consensus.
                RouterMicrodesc filteredRelay = clientState.microdescConsensus.findWithHash(microdescHash);
                if (filteredRelay != null) filtered.add(filteredRelay);
                else {
                    // This should never happen, as the client does not currently update its consensus mid-run.
                    logger.error("Mismatched microdesc consensus and stored relay.");
                    return false;
                }
            }
            // Set the filtered relays for the client to the ones we just loaded.
            clientState.vanguardsLite.getGuardSystem().setFiltered(filtered);
            ArrayList<RouterMicrodesc> primary = new ArrayList<>();
            // Read the number of primary guards in use.
            int primaryGuards = inputStream.readUShort();
            for (int i = 0; i < primaryGuards; i++) {
                // Read the microdesc hash for the relay.
                byte[] microdescHash = inputStream.readNBytes(32);
                // Read the guard's lifetime (long).
                long rotate = inputStream.readLong();
                // Find the relay in the microdesc consensus.
                RouterMicrodesc primaryGuard = clientState.microdescConsensus.findWithHash(microdescHash);
                if (primaryGuard != null) primary.add(primaryGuard);
                else {
                    // This should never happen, as the client does not currently update its consensus mid-run.
                    logger.error("Mismatched microdesc consensus and stored guard.");
                    return false;
                }
            }
            // Set the primary guards for the client to the ones we just loaded.
            clientState.vanguardsLite.getGuardSystem().setPrimary(primary);
            // Load the serialised vanguards second layer data.
            // Read the number of second layer vanguards.
            int secondLayerVanguards = inputStream.readUShort();
            for (int i = 0; i < secondLayerVanguards; i++) {
                // Read the vanguard's microdesc hash.
                byte[] microdescHash = inputStream.readNBytes(32);
                RouterMicrodesc vanguardRelay = clientState.microdescConsensus.findWithHash(microdescHash);
                // Read the vanguard's rotation time (long).
                long rotate = inputStream.readLong();
                // Create a new vanguard instance from the relay if it was found. If the relay is null, then set the new variable to null.
                VanguardsLayer.Vanguard vanguard = vanguardRelay == null ? null : new VanguardsLayer.Vanguard(vanguardRelay, rotate);
                // Update the vanguard at the current index in the second layer.
                clientState.vanguardsLite.getSecondLayer().setVanguard(i, vanguard);
            }

            // Finally, close the cache file input stream.
            inputStream.close();
            logger.info("Client data loaded from cache file.");
            return true;
        } catch (IOException e) {
            logger.error("Failed to read cache file " + cacheFilePath + ".");
            return false;
        }
    }

}
