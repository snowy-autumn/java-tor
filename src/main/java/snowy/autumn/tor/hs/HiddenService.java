package snowy.autumn.tor.hs;

import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class HiddenService {

    OnionAddress onionAddress;
    MicrodescConsensus microdescConsensus;

    public static class HSDir {

        RouterMicrodesc microdesc;
        byte[] hsRelayIndex;

        public HSDir(RouterMicrodesc microdesc, byte[] hsRelayIndex) {
            this.microdesc = microdesc;
            this.hsRelayIndex = hsRelayIndex;
        }

        public byte[] setHsRelayIndex(byte[] hsRelayIndex) {
            return this.hsRelayIndex = hsRelayIndex;
        }

        public RouterMicrodesc getMicrodesc() {
            return microdesc;
        }
    }

    public HiddenService(MicrodescConsensus microdescConsensus, String hsAddress) {
        this.microdescConsensus = microdescConsensus;
        this.onionAddress = new OnionAddress(hsAddress);
    }

    public static int getPeriodLength() {
        // The consensus doesn't usually list hsdir_interval, so we'll just always assume it's the default, at 1440.
        return 1440;
    }

    public static long getCurrentPeriod() {
        long unixTimeInMinutes = Instant.now().getEpochSecond() / 60;
        unixTimeInMinutes -= 12 * 60;
        unixTimeInMinutes /= getPeriodLength();
        return unixTimeInMinutes;
    }

    public static byte[] hsRelayIndex(byte[] srv, byte[] ed25519Id) {
        MessageDigest sha3_256 = Cryptography.createDigest("SHA3-256");
        sha3_256.update("node-idx".getBytes());
        sha3_256.update(ed25519Id);
        sha3_256.update(srv);
        sha3_256.update(ByteBuffer.allocate(8).putLong(HiddenService.getCurrentPeriod()).array());
        sha3_256.update(ByteBuffer.allocate(8).putLong(HiddenService.getPeriodLength()).array());
        return sha3_256.digest();
    }

    public HashSet<RouterMicrodesc> possibleFetchDirectories() {
        ArrayList<HSDir> hsDirs = new ArrayList<>(microdescConsensus.getHsDirs());
        MessageDigest sha3_256 = Cryptography.createDigest("SHA3-256");
        HashSet<RouterMicrodesc> potentialHsDirs = new HashSet<>();
        for (int replicanum = 1; replicanum < microdescConsensus.hsDirNReplicas() + 1; replicanum++) {
            sha3_256.update("store-at-idx".getBytes());
            sha3_256.update(onionAddress.blindedPublicKey());
            sha3_256.update(ByteBuffer.allocate(8).putLong(replicanum).array());
            // Todo: Change this to use the valid-after time from the consensus.
            sha3_256.update(ByteBuffer.allocate(8).putLong(HiddenService.getPeriodLength()).array());
            sha3_256.update(ByteBuffer.allocate(8).putLong(HiddenService.getCurrentPeriod()).array());
            byte[] replica = sha3_256.digest();

            int fetch = microdescConsensus.hsDirSpreadFetch();

            for (HSDir hsDir : hsDirs) {
                if (Arrays.compareUnsigned(replica, hsDir.hsRelayIndex) < 0) {
                    potentialHsDirs.add(hsDir.getMicrodesc());
                    if (--fetch == 0) break;
                }
            }
        }

        return potentialHsDirs;
    }

    public OnionAddress getOnionAddress() {
        return onionAddress;
    }
}
