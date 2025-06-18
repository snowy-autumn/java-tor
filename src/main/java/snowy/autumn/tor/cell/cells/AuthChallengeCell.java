package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

public class AuthChallengeCell extends Cell {

    public AuthChallengeCell() {
        super(0, AUTH_CHALLENGE);
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
