package snowy.autumn.tor.hs;

import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
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

        public byte[] calculateHsRelayIndexConditional(byte[] srv) {
            if (this.hsRelayIndex.length == 0) return this.hsRelayIndex = HiddenService.hsRelayIndex(srv, microdesc.getEd25519Id());
            return this.hsRelayIndex;
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

    public static ZonedDateTime getCurrentTime() {
        return Instant.now().atZone(ZoneOffset.UTC);
    }

    public static long getCurrentTimePeriod() {
        long unixTimeInMinutes = getCurrentTime().toEpochSecond() / 60;
        unixTimeInMinutes -= 12 * 60;
        unixTimeInMinutes /= getPeriodLength();
        return unixTimeInMinutes;
    }

    public static byte[] hsRelayIndex(byte[] srv, byte[] ed25519Id) {
        MessageDigest sha3_256 = Cryptography.createDigest("SHA3-256");
        sha3_256.update("node-idx".getBytes());
        sha3_256.update(ed25519Id);
        sha3_256.update(srv);
        sha3_256.update(ByteBuffer.allocate(8).putLong(HiddenService.getCurrentTimePeriod()).array());
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
            sha3_256.update(ByteBuffer.allocate(8).putLong(HiddenService.getCurrentTimePeriod()).array());
            byte[] replica = sha3_256.digest();

            int fetchIndex = 0;

            for (HSDir hsDir : hsDirs) {
                if (Arrays.compareUnsigned(replica, hsDir.hsRelayIndex) < 0) break;
                fetchIndex++;
            }

            for (int i = 0; i < microdescConsensus.hsDirSpreadFetch(); i++) {
                potentialHsDirs.add(hsDirs.get((fetchIndex + i) % hsDirs.size()).getMicrodesc());
            }
        }

        return potentialHsDirs;
    }

    public OnionAddress getOnionAddress() {
        return onionAddress;
    }
}
