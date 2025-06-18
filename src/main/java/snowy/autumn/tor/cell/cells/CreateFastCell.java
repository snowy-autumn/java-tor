package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CreateFastCell extends Cell {

    byte[] keyMaterial;

    public CreateFastCell(int circuitId) {
        super(circuitId, CREATE_FAST);
        keyMaterial = new byte[20];
        try {
            SecureRandom.getInstanceStrong().nextBytes(keyMaterial);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected byte[] serialiseBody() {
        return keyMaterial;
    }

    public byte[] getKeyMaterial() {
        return keyMaterial;
    }
}
