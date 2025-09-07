package snowy.autumn.tor.vanguards;

import snowy.autumn.tor.directory.documents.RouterMicrodesc;
import snowy.autumn.tor.relay.Guard;

public record VanguardsGuard(Guard guard, RouterMicrodesc guardMicrodesc) {
}
