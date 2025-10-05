package snowy.autumn.tor.client;

import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class GuardSystem {

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
        List<RouterMicrodesc> guardMicrodescs = microdescConsensus.getAllWithFlags(RouterMicrodesc.Flags.GUARD, RouterMicrodesc.Flags.V2DIR);
        // Todo: Replace with the appropriate weighted shuffling algorithm.
        Collections.shuffle(guardMicrodescs);
        sampled.addAll(guardMicrodescs.stream().limit(sampleSize).toList());
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
        for (RouterMicrodesc routerMicrodesc : sampled)
            if ((guardInfo = attemptGuard(routerMicrodesc)) != null) break;
        if (guardInfo == null) return null;

        if (primaryFull()) {
            try {
                guardInfo.guard().terminate();
            }
            catch (Exception ignored) {}
            filtered.add(guardInfo.guardMicrodesc());
        }
        else primary.add(guardInfo);

        return guardInfo;
    }

    public Guard getRandomPrimaryGuard() {
        int index = random.nextInt(primarySize);
        Guard.GuardInfo guardInfo = primary.size() > index ? primary.get(index) : null;
        if (guardInfo != null) return guardInfo.guard();
        if ((guardInfo = promoteNextGuard()) != null) return guardInfo.guard();
        else return null;
    }

}
