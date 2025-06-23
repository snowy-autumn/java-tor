package snowy.autumn.tor.circuit;

public class Stream {

    short streamId;

    static final int WINDOW_INIT = 500;

    int deliverWindow = WINDOW_INIT;

    public Stream(short streamId) {
        this.streamId = streamId;
    }

    public void received(Circuit circuit, byte[] digest) {
        if (--deliverWindow <= 450) {
            circuit.handleSendMe(streamId, digest);
            deliverWindow += 50;
        }
    }

}
