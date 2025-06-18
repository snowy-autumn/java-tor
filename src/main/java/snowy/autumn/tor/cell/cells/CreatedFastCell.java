package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.crypto.Keys;

import java.util.Arrays;

public class CreatedFastCell extends Cell {

    byte[] keyMaterial;
    byte[] derivativeKeyData;

    public CreatedFastCell(int circuitId, byte[] keyMaterial, byte[] derivativeKeyData) {
        super(circuitId, CREATED_FAST);
        this.keyMaterial = keyMaterial;
        this.derivativeKeyData = derivativeKeyData;
    }

    public boolean verify(Keys keys) {
        return Arrays.equals(keys.KH(), derivativeKeyData);
    }

    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }

    public byte[] getKeyMaterial() {
        return keyMaterial;
    }

}
