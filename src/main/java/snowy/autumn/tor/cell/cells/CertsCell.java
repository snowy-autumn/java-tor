package snowy.autumn.tor.cell.cells;

import snowy.autumn.tor.cell.Cell;

public class CertsCell extends Cell {

    public record Cert(byte type, short length, byte[] encodedCert) {

    }

    Cert[] certs;

    public CertsCell(Cert[] certs) {
        super(0, CERTS);
        this.certs = certs;
    }

    public boolean verifyCertificates() {
        // Todo: Implement certificate verification.
        return true;
    }

    @ClientDoesNotImplement
    @Override
    protected byte[] serialiseBody() {
        return new byte[0];
    }
}
