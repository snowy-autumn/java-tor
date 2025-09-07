package snowy.autumn.tor.vanguards;

import snowy.autumn.tor.directory.documents.MicrodescConsensus;
import snowy.autumn.tor.directory.documents.RouterMicrodesc;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class VanguardsLayer {

    public static class Vanguard {

        long selection;
        RouterMicrodesc routerMicrodesc;

        public Vanguard(RouterMicrodesc routerMicrodesc) {
            selection = Instant.now().getEpochSecond();
            this.routerMicrodesc = routerMicrodesc;
        }

        public RouterMicrodesc getRouterMicrodesc() {
            return routerMicrodesc;
        }
    }

    Random random = new Random();

    Vanguard[] vanguards;
    MicrodescConsensus microdescConsensus;

    public VanguardsLayer(MicrodescConsensus microdescConsensus, int size, VanguardsLayer... otherLayers) {
        this.vanguards = new Vanguard[size];
        this.microdescConsensus = microdescConsensus;
        for (int i = 0; i < size; i++) {
            rotateVanguard(i, otherLayers);
        }
    }

    public VanguardsLayer(MicrodescConsensus microdescConsensus, Vanguard[] vanguards, VanguardsLayer... otherLayers) {
        this.vanguards = vanguards;
        for (int i = 0; i < vanguards.length; i++) {
            if (!vanguardExistsInConsensus(i)) {
                rotateVanguard(i, otherLayers);
            }
        }
    }

    private void rotateVanguard(int index, VanguardsLayer[] vanguardsLayers) {
        List<RouterMicrodesc> microdescs = microdescConsensus.getMicrodescs().stream()
                .filter(microdesc ->
                        Arrays.stream(vanguards).noneMatch(vanguard -> vanguard.getRouterMicrodesc().equals(microdesc)))
                .filter(microdesc ->
                        Arrays.stream(vanguardsLayers).noneMatch(vanguardsLayer ->
                                Arrays.stream(vanguardsLayer.vanguards)
                                        .anyMatch(vanguard -> vanguard.getRouterMicrodesc().equals(microdesc))))
                .toList();
        vanguards[index] = new Vanguard(microdescs.get(random.nextInt(microdescs.size())));
    }

    private boolean vanguardExistsInConsensus(int index) {
        return microdescConsensus.getMicrodescs().stream().anyMatch(microdesc -> vanguards[index].getRouterMicrodesc().equals(microdesc));
    }

    public Vanguard getRandom() {
        return vanguards[random.nextInt(vanguards.length)];
    }

    public Vanguard replaceBadVanguard(RouterMicrodesc routerMicrodesc, VanguardsLayer... otherLayers) {
        for (int i = 0; i < vanguards.length; i++) {
            if (vanguards[i].getRouterMicrodesc().equals(routerMicrodesc)) {
                rotateVanguard(i, otherLayers);
                return vanguards[i];
            }
        }
        return null;
    }

}
