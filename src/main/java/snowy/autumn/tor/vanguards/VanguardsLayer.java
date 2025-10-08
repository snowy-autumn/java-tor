package snowy.autumn.tor.vanguards;

import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.RouterMicrodescList;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class VanguardsLayer implements RouterMicrodescList {

    public static class Vanguard {

        long rotate;
        RouterMicrodesc routerMicrodesc;

        public Vanguard(RouterMicrodesc routerMicrodesc, long rotate) {
            this.routerMicrodesc = routerMicrodesc;
            this.rotate = rotate;
        }

        public RouterMicrodesc getRouterMicrodesc() {
            return routerMicrodesc;
        }

        public boolean shouldRotate() {
            return Instant.now().getEpochSecond() >= rotate;
        }

        public long getRotate() {
            return rotate;
        }
    }

    Random random = new Random();

    Vanguard[] vanguards;
    List<RouterMicrodesc> microdescs;

    public VanguardsLayer(List<RouterMicrodesc> microdescs, int size, RouterMicrodescList... otherLayers) {
        this.vanguards = new Vanguard[size];
        this.microdescs = microdescs;
        for (int i = 0; i < size; i++) {
            rotateVanguard(i, otherLayers);
        }
    }

    public VanguardsLayer(List<RouterMicrodesc> microdescs, Vanguard[] vanguards, RouterMicrodescList... otherLayers) {
        this.vanguards = vanguards;
        this.microdescs = microdescs;
        for (int i = 0; i < vanguards.length; i++) {
            if (!vanguardExistsInConsensus(i)) {
                rotateVanguard(i, otherLayers);
            }
        }
    }

    private void rotateVanguard(int index, RouterMicrodescList[] layers) {
        List<RouterMicrodesc> microdescs = this.microdescs.stream()
                .filter(microdesc ->
                        Arrays.stream(vanguards).noneMatch(vanguard -> vanguard != null && vanguard.getRouterMicrodesc().equals(microdesc)))
                .filter(microdesc ->
                        Arrays.stream(layers).noneMatch(layer ->
                                layer.getMicrodescs().stream()
                                        .anyMatch(routerMicrodesc -> routerMicrodesc != null && routerMicrodesc.equals(microdesc))))
                .toList();
        // Todo: Replace this temporary random distribution with the actual relevant distribution.
        vanguards[index] = new Vanguard(microdescs.get(random.nextInt(microdescs.size())), Instant.now().getEpochSecond() + (long) new Random().nextInt(3, 14) * 60 * 60 * 24);
    }

    private boolean vanguardExistsInConsensus(int index) {
        return microdescs.stream().anyMatch(microdesc -> vanguards[index].getRouterMicrodesc().equals(microdesc));
    }

    public Vanguard getRandom() {
        return vanguards[random.nextInt(vanguards.length)];
    }

    public Vanguard replaceBadVanguard(RouterMicrodesc routerMicrodesc, RouterMicrodescList... otherLayers) {
        for (int i = 0; i < vanguards.length; i++) {
            if (vanguards[i].getRouterMicrodesc().equals(routerMicrodesc)) {
                rotateVanguard(i, otherLayers);
                return vanguards[i];
            }
        }
        return null;
    }

    public void fixAll(RouterMicrodescList... otherLayers) {
        for (int i = 0; i < vanguards.length; i++) {
            if (vanguards[i] == null || vanguards[i].shouldRotate()) {
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

    @Override
    public List<RouterMicrodesc> getMicrodescs() {
        return Arrays.stream(vanguards).map(Vanguard::getRouterMicrodesc).toList();
    }

}
