package snowy.autumn.tor.cell.cells.relay.commands;

import snowy.autumn.tor.cell.cells.relay.RelayCell;

import java.nio.ByteBuffer;

public class SendMeCommand extends RelayCell {

    int sendMeVersion;
    byte[] digest;

    public SendMeCommand(int circuitId, short streamId, int sendMeVersion, byte[] digest) {
        super(circuitId, false, SENDME, streamId);
        this.sendMeVersion = sendMeVersion;
        this.digest = digest;
    }

    public SendMeCommand(int circuitId, short streamId, int sendMeVersion) {
        this(circuitId, streamId, sendMeVersion, null);
    }

    @Override
    protected byte[] serialiseRelayBody() {
        if (sendMeVersion == 0 || digest == null) return new byte[1];
        return ByteBuffer.allocate(1 + 2 + digest.length)
                .put((byte) sendMeVersion)
                .putShort((short) digest.length)
                .put(digest).array();
    }

    public int getSendMeVersion() {
        return sendMeVersion;
    }

    public byte[] getDigest() {
        return digest;
    }
}
