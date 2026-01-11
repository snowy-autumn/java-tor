package snowy.autumn.tor.vanguards;

import snowy.autumn.tor.circuit.CanExtendTo;
import snowy.autumn.tor.client.GuardSystem;
import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;

import java.util.Arrays;
import java.util.List;

public class VanguardsLite {

    GuardSystem guardSystem;
    VanguardsLayer secondLayer;
    MicrodescConsensus microdescConsensus;
    List<RouterMicrodesc> microdescs;

    public VanguardsLite(MicrodescConsensus microdescConsensus) {
        this.microdescConsensus = microdescConsensus;
        microdescs = microdescConsensus.getMicrodescs();
        guardSystem = new GuardSystem(microdescConsensus);
        secondLayer = new VanguardsLayer(microdescs, 4, guardSystem);
    }

    public Guard.GuardInfo getEntryGuard(CanExtendTo... existingNodes) {
        Guard.GuardInfo primaryGuardInfo = null;
        while (primaryGuardInfo == null) {
            primaryGuardInfo = guardSystem.getRandomPrimaryGuardInfo();
            if (existingNodes != null && Arrays.asList(existingNodes).contains(primaryGuardInfo.guardMicrodesc()))
                primaryGuardInfo = null;
        }
        return primaryGuardInfo;
    }

    public Guard.GuardInfo getEntryGuard() {
        return guardSystem.getRandomPrimaryGuardInfo();
    }

    public RouterMicrodesc getSecondLayerVanguard(CanExtendTo... existingNodes) {
        RouterMicrodesc secondLayerMicrodesc = null;
        while (secondLayerMicrodesc == null) {
            VanguardsLayer.Vanguard vanguard = secondLayer.getRandom();
            if (vanguard == null) {
                fixAll();
                vanguard = secondLayer.getRandom();
                if (vanguard == null) return null;
            }
            secondLayerMicrodesc = vanguard.getRouterMicrodesc();
            if (existingNodes != null && Arrays.asList(existingNodes).contains(secondLayerMicrodesc))
                secondLayerMicrodesc = null;
        }
        return secondLayerMicrodesc;
    }

    public RouterMicrodesc getSecondLayerVanguard() {
        return secondLayer.getRandom().getRouterMicrodesc();
    }

    public RouterMicrodesc replaceBadRelay(RouterMicrodesc routerMicrodesc) {
        Guard.GuardInfo newGuard = guardSystem.replaceBadGuard(routerMicrodesc);
        if (newGuard != null) return newGuard.guardMicrodesc();
        VanguardsLayer.Vanguard newVanguard = secondLayer.replaceBadVanguard(routerMicrodesc, guardSystem);
        if (newVanguard != null) return newVanguard.getRouterMicrodesc();
        throw new RuntimeException("Attempted to replace a bad vanguard that does not exist in the mesh.");
    }

    public void fixAll() {
        secondLayer.fixAll(guardSystem);
    }

    public GuardSystem getGuardSystem() {
        return guardSystem;
    }

    public VanguardsLayer getSecondLayer() {
        return secondLayer;
    }
}
