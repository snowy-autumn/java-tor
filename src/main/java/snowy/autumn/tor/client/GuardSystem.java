package snowy.autumn.tor.client;

import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;
import snowy.autumn.tor.relay.RouterMicrodescList;

import java.util.*;

public class GuardSystem implements RouterMicrodescList {

    int sampleSize = 20;
    int primarySize = 2;

    MicrodescConsensus microdescConsensus;
    ArrayList<RouterMicrodesc> sampled = new ArrayList<>();
    // Note: Filtered here means usable_filtered.
    ArrayList<RouterMicrodesc> filtered = new ArrayList<>();
    ArrayList<Guard.GuardInfo> primary = new ArrayList<>();

    Random random = new Random();

    public GuardSystem(MicrodescConsensus microdescConsensus) {
        primary.ensureCapacity(primarySize);
        this.microdescConsensus = microdescConsensus;
        initSampled();
    }

    public void initSampled() {
        ArrayList<RouterMicrodesc> guardMicrodescs = new ArrayList<>(microdescConsensus.getAllWithFlags(RouterMicrodesc.Flags.GUARD, RouterMicrodesc.Flags.V2DIR));
        // Todo: Replace with the appropriate weighted shuffling algorithm.
        Collections.shuffle(guardMicrodescs);
        sampled.addAll(guardMicrodescs.stream().limit(Math.max(0, guardMicrodescs.size() - sampleSize)).toList());
    }

    private boolean primaryFull() {
        return primary.size() == primarySize;
    }

    private Guard.GuardInfo attemptGuard(RouterMicrodesc routerMicrodesc) {
        Guard guard = new Guard(routerMicrodesc);
        if (!guard.connect()) return null;
        if (!guard.generalTorHandshake()) {
            try {
                guard.terminate();
            }
            catch (Exception ignored) {}
            return null;
        }
        guard.startCellListener();
        return new Guard.GuardInfo(guard, routerMicrodesc);
    }
    private Guard.GuardInfo promoteNextGuard() {
        Guard.GuardInfo guardInfo = null;
        for (RouterMicrodesc routerMicrodesc : filtered)
            if ((guardInfo = attemptGuard(routerMicrodesc)) != null) break;
        if (guardInfo == null) {
            for (RouterMicrodesc routerMicrodesc : sampled)
                if ((guardInfo = attemptGuard(routerMicrodesc)) != null) break;
            if (guardInfo == null) return null;
        }

        if (primaryFull()) {
            try {
                guardInfo.guard().terminate();
            }
            catch (Exception ignored) {}
            sampled.remove(guardInfo.guardMicrodesc());
            filtered.add(guardInfo.guardMicrodesc());
        }
        else {
            filtered.remove(guardInfo.guardMicrodesc());
            primary.add(guardInfo);
        }

        return guardInfo;
    }

    public Guard.GuardInfo getRandomPrimaryGuardInfo() {
        int index = random.nextInt(primarySize);
        Guard.GuardInfo guardInfo = primary.size() > index ? primary.get(index) : null;
        if (guardInfo != null) return guardInfo;
        if ((guardInfo = promoteNextGuard()) != null) return guardInfo;
        else return null;
    }

    public Guard.GuardInfo replaceBadGuard(RouterMicrodesc routerMicrodesc) {
        if (!primary.removeIf(primaryGuard -> primaryGuard.guardMicrodesc().equals(routerMicrodesc))) return null;
        return promoteNextGuard();
    }

    public ArrayList<Guard.GuardInfo> getPrimary() {
        return primary;
    }

    public void setSampled(ArrayList<RouterMicrodesc> sampled) {
        this.sampled = sampled;
        this.sampled.removeIf(Objects::isNull);
    }

    public void setFiltered(ArrayList<RouterMicrodesc> filtered) {
        this.filtered = filtered;
        this.filtered.removeIf(Objects::isNull);
    }

    public void setPrimary(ArrayList<RouterMicrodesc> primary) {
        for (RouterMicrodesc routerMicrodesc : primary) {
            Guard.GuardInfo guardInfo = attemptGuard(routerMicrodesc);
            this.primary.add(guardInfo);
        }
        this.primary.removeIf(Objects::isNull);
    }

    public ArrayList<RouterMicrodesc> getSampled() {
        return sampled;
    }

    public ArrayList<RouterMicrodesc> getFiltered() {
        return filtered;
    }

    @Override
    public List<RouterMicrodesc> getMicrodescs() {
        return new ArrayList<>(sampled);
    }
}
