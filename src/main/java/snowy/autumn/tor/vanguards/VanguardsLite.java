package snowy.autumn.tor.vanguards;

import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class VanguardsLite {

    VanguardsLayer entryLayer;
    VanguardsGuard[] entryGuards;
    VanguardsLayer secondLayer;
    MicrodescConsensus microdescConsensus;
    List<RouterMicrodesc> microdescs;
    Random random = new Random();

    public VanguardsLite(MicrodescConsensus microdescConsensus) {
        this.microdescConsensus = microdescConsensus;
        microdescs = microdescConsensus.getMicrodescs();
        entryLayer = new VanguardsLayer(microdescConsensus.getAllWithFlags(RouterMicrodesc.Flags.GUARD), 2);
        entryGuards = Arrays.stream(entryLayer.getVanguards()).map(vanguard -> new VanguardsGuard(new Guard(vanguard.getRouterMicrodesc()), vanguard.getRouterMicrodesc())).toList().toArray(new VanguardsGuard[0]);
        secondLayer = new VanguardsLayer(microdescs, 4, entryLayer);
    }

    public VanguardsGuard getEntryGuard() {
        int guardIndex = random.nextInt(entryGuards.length);
        Guard guard = entryGuards[guardIndex].guard();
        boolean connected = guard.isConnected();
        if (!connected) {
            while (!connected) {
                for (int i = 0; i < 3; i++) {
                    if (connected = guard.connect()) break;
                }
                if (connected) {
                    if (connected = guard.generalTorHandshake()) continue;
                    else guard.terminate();
                }
                RouterMicrodesc guardMicrodesc = replaceBadVanguard(entryLayer.getVanguards()[guardIndex].getRouterMicrodesc());
                guard = new Guard(guardMicrodesc);
                entryGuards[guardIndex] = new VanguardsGuard(guard, guardMicrodesc);
            }
            guard.startCellListener();
        }

        return entryGuards[guardIndex];
    }

    public RouterMicrodesc getSecondLayerVanguard() {
        return secondLayer.getRandom().getRouterMicrodesc();
    }

    public RouterMicrodesc replaceBadVanguard(RouterMicrodesc routerMicrodesc) {
        VanguardsLayer.Vanguard newVanguard = entryLayer.replaceBadVanguard(routerMicrodesc, secondLayer);
        if (newVanguard != null) return newVanguard.getRouterMicrodesc();
        newVanguard = secondLayer.replaceBadVanguard(routerMicrodesc, entryLayer);
        if (newVanguard != null) return newVanguard.getRouterMicrodesc();
        throw new RuntimeException("Attempted to replace a bad vanguard that does not exist in the mesh.");
    }

    public void fixAll() {
        entryLayer.fixAll();
        secondLayer.fixAll(entryLayer);
    }

    public VanguardsLayer getEntryLayer() {
        return entryLayer;
    }

    public VanguardsLayer getSecondLayer() {
        return secondLayer;
    }
}
