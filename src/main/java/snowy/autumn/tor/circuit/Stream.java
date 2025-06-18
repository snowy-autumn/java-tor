package snowy.autumn.tor.circuit;

public class Stream {

    short streamId;

    static final int WINDOW_INIT = 500;
    int total = 0;

    int deliverWindow = WINDOW_INIT;

    public Stream(short streamId) {
        this.streamId = streamId;
    }

    public void received(Circuit circuit) {
        total++;
        if (--deliverWindow <= 450) {
            circuit.handleSendMe(streamId);
            deliverWindow += 50;
        }
    }

}
