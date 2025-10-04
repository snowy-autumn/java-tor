package snowy.autumn.tor.client;

import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.util.Collections;
import java.util.List;

public class GuardSystem {

    int sampleSize = 20;
    int primarySize = 2;

    MicrodescConsensus microdescConsensus;

    public GuardSystem(MicrodescConsensus microdescConsensus) {
        this.microdescConsensus = microdescConsensus;
        List<RouterMicrodesc> guardMicrodescs = microdescConsensus.getAllWithFlags(RouterMicrodesc.Flags.GUARD, RouterMicrodesc.Flags.V2DIR);
        // Todo: Replace with the appropriate weighted shuffling algorithm.
        Collections.shuffle(guardMicrodescs);
        guardMicrodescs = guardMicrodescs.stream().limit(sampleSize).toList();
    }

}
