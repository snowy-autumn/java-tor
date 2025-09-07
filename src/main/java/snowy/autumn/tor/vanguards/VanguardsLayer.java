package snowy.autumn.tor.vanguards;

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
    List<RouterMicrodesc> microdescs;

    public VanguardsLayer(List<RouterMicrodesc> microdescs, int size, VanguardsLayer... otherLayers) {
        this.vanguards = new Vanguard[size];
        this.microdescs = microdescs;
        for (int i = 0; i < size; i++) {
            rotateVanguard(i, otherLayers);
        }
    }

    public VanguardsLayer(List<RouterMicrodesc> microdescs, Vanguard[] vanguards, VanguardsLayer... otherLayers) {
        this.vanguards = vanguards;
        this.microdescs = microdescs;
        for (int i = 0; i < vanguards.length; i++) {
            if (!vanguardExistsInConsensus(i)) {
                rotateVanguard(i, otherLayers);
            }
        }
    }

    private void rotateVanguard(int index, VanguardsLayer[] vanguardsLayers) {
        List<RouterMicrodesc> microdescs = this.microdescs.stream()
                .filter(microdesc ->
                        Arrays.stream(vanguards).noneMatch(vanguard -> vanguard != null && vanguard.getRouterMicrodesc().equals(microdesc)))
                .filter(microdesc ->
                        Arrays.stream(vanguardsLayers).noneMatch(vanguardsLayer ->
                                Arrays.stream(vanguardsLayer.vanguards)
                                        .anyMatch(vanguard -> vanguard != null && vanguard.getRouterMicrodesc().equals(microdesc))))
                .toList();
        vanguards[index] = new Vanguard(microdescs.get(random.nextInt(microdescs.size())));
    }

    private boolean vanguardExistsInConsensus(int index) {
        return microdescs.stream().anyMatch(microdesc -> vanguards[index].getRouterMicrodesc().equals(microdesc));
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

    public void fixAll(VanguardsLayer... otherLayers) {
        for (int i = 0; i < vanguards.length; i++) {
            if (vanguards[i] == null) {
                rotateVanguard(i, otherLayers);
            }
        }
    }

    public Vanguard[] getVanguards() {
        return vanguards;
    }

    public void setVanguard(int index, Vanguard vanguard) {
        vanguards[index] = vanguard;
    }

}
