package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

import java.util.Arrays;

public class VersionCell extends Cell {

    int[] versions;

    public VersionCell(int[] versions) {
        super(0, VERSIONS);
        this.versions = versions;
        Arrays.sort(this.versions);
    }

    @Override
    protected byte[] serialiseBody() {
        byte[] body = new byte[versions.length * 2];
        for (int i = 0; i < versions.length; i++) {
            body[i * 2] = (byte) (versions[i] >> 8);
            body[i * 2 + 1] = (byte) (versions[i] & 0xFF);
        }
        return body;
    }

    public int highestSharedVersion(VersionCell versionCell) {
        int highestVersion = 0;
        for (int version : versionCell.versions) {
            if (Arrays.stream(versions).anyMatch(v -> v == version))
                highestVersion = Math.max(highestVersion, version);
        }
        return highestVersion;
    }

}
