package snowy.autumn.tor.vanguards;

import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;

public class VanguardsLite {

    VanguardsLayer entryLayer;
    VanguardsLayer secondLayer;
    MicrodescConsensus microdescConsensus;

    public VanguardsLite(MicrodescConsensus microdescConsensus) {
        this.microdescConsensus = microdescConsensus;
        entryLayer = new VanguardsLayer(microdescConsensus, 2);
        secondLayer = new VanguardsLayer(microdescConsensus, 4, entryLayer);
    }

    public RouterMicrodesc getEntryGuard() {
        return entryLayer.getRandom().getRouterMicrodesc();
    }

    public RouterMicrodesc getSecondLayerGuard() {
        return secondLayer.getRandom().getRouterMicrodesc();
    }

    public RouterMicrodesc replaceBadVanguard(RouterMicrodesc routerMicrodesc) {
        VanguardsLayer.Vanguard newVanguard = entryLayer.replaceBadVanguard(routerMicrodesc, secondLayer);
        if (newVanguard != null) return newVanguard.getRouterMicrodesc();
        newVanguard = secondLayer.replaceBadVanguard(routerMicrodesc, entryLayer);
        if (newVanguard != null) return newVanguard.getRouterMicrodesc();
        throw new RuntimeException("Attempted to replace a bad vanguard that does not exist in the mesh.");
    }

}
