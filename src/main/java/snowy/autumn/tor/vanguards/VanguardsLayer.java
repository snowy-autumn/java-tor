package snowy.autumn.tor.vanguards;

import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.RouterMicrodescList;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
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

    ArrayList<Vanguard> vanguards;
    List<RouterMicrodesc> microdescs;

    public VanguardsLayer(List<RouterMicrodesc> microdescs, int size, RouterMicrodescList... otherLayers) {
        this.vanguards = new ArrayList<>(Collections.nCopies(size, null));
        this.microdescs = microdescs;
        for (int i = 0; i < size; i++) {
            rotateVanguard(i, otherLayers);
        }
    }

    public VanguardsLayer(List<RouterMicrodesc> microdescs, ArrayList<Vanguard> vanguards, RouterMicrodescList... otherLayers) {
        this.vanguards = vanguards;
        this.microdescs = microdescs;
        for (int i = 0; i < vanguards.size(); i++) {
            if (!vanguardExistsInConsensus(i)) {
                rotateVanguard(i, otherLayers);
            }
        }
    }

    private void rotateVanguard(int index, RouterMicrodescList[] layers) {
        // Here I used a double loop solution, instead of the old stream one, to save memory.
        // There probably is a much better solution, but right now, this works fine.
        int filtered = 0;
        for (RouterMicrodesc routerMicrodesc : microdescs) {
            if (routerMicrodesc == null) continue;
            boolean exists = false;
            for (Vanguard vanguard : vanguards) {
                if (vanguard != null && vanguard.getRouterMicrodesc().equals(routerMicrodesc)) {
                    exists = true;
                    break;
                }
            }
            for (RouterMicrodescList layer : layers) {
                if (exists = layer.getMicrodescs().contains(routerMicrodesc))
                    break;
            }
            if (!exists) filtered++;
        }
        for (RouterMicrodesc routerMicrodesc : microdescs) {
            if (routerMicrodesc == null) continue;
            boolean exists = false;
            for (Vanguard vanguard : vanguards) {
                if (vanguard != null && vanguard.getRouterMicrodesc().equals(routerMicrodesc)) {
                    exists = true;
                    break;
                }
            }
            for (RouterMicrodescList layer : layers) {
                if (exists = layer.getMicrodescs().contains(routerMicrodesc))
                    break;
            }
            if (!exists && --filtered == 0) {
                // Todo: Replace this temporary random distribution with the actual relevant distribution.
                vanguards.set(index, new Vanguard(routerMicrodesc, Instant.now().getEpochSecond() + (long) new Random().nextInt(3, 14) * 60 * 60 * 24));
                break;
            }
        }
    }

    private boolean vanguardExistsInConsensus(int index) {
        return microdescs.stream().anyMatch(microdesc -> vanguards.get(index).getRouterMicrodesc().equals(microdesc));
    }

    public Vanguard getRandom() {
        return vanguards.get(random.nextInt(vanguards.size()));
    }

    public Vanguard replaceBadVanguard(RouterMicrodesc routerMicrodesc, RouterMicrodescList... otherLayers) {
        for (int i = 0; i < vanguards.size(); i++) {
            if (vanguards.get(i).getRouterMicrodesc().equals(routerMicrodesc)) {
                rotateVanguard(i, otherLayers);
                return vanguards.get(i);
            }
        }
        return null;
    }

    public void fixAll(RouterMicrodescList... otherLayers) {
        // Todo: Change the client's behaviour so that if we're trying to fetch a new microdesc consensus, vanguards will not be rotated but simply removed.
        for (int i = 0; i < vanguards.size(); i++) {
            if (vanguards.get(i) == null || vanguards.get(i).shouldRotate()) {
                rotateVanguard(i, otherLayers);
            }
        }
    }

    public ArrayList<Vanguard> getVanguards() {
        return vanguards;
    }

    public void setVanguard(int index, Vanguard vanguard) {
        vanguards.set(index, vanguard);
    }

    @Override
    public List<RouterMicrodesc> getMicrodescs() {
        return vanguards.stream().map(Vanguard::getRouterMicrodesc).toList();
    }

}
