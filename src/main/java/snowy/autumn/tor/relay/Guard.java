package snowy.autumn.tor.relay;

import snowy.autumn.tor.cell.Cell;
import snowy.autumn.tor.cell.cells.*;
import snowy.autumn.tor.circuit.Circuit;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.locks.ReentrantLock;

public class Guard extends Relay {

    private SSLSocket socket;
    private InputStream inputStream;
    private OutputStream outputStream;
    private final ReentrantLock outputLock = new ReentrantLock();
    private final ReentrantLock inputLock = new ReentrantLock();
    byte highestSupportedVersion;
    boolean connected;

    private final ReentrantLock circuitsLock = new ReentrantLock();
    private final HashMap<Integer, Circuit> circuitHashMap = new HashMap<>();

    public Guard(String host, int port, byte[] fingerprint) {
        super(host, port, fingerprint);
    }

    protected boolean write(byte[] data) {
        outputLock.lock();
        try {
            outputStream.write(data);
            return true;
        } catch (IOException e) {
            return false;
        }
        finally {
            outputLock.unlock();
        }
    }

    public byte[] reactExact(int length) {
        inputLock.lock();
        try {
            return inputStream.readNBytes(length);
        } catch (IOException e) {
            return terminated();
        } finally {
            inputLock.unlock();
        }
    }

    public byte[] read(int maxLength) {
        inputLock.lock();
        try {
            byte[] buffer = new byte[maxLength];
            int bytesRead = inputStream.read(buffer);
            if (bytesRead == 0) return terminated();
            if (bytesRead == maxLength) return buffer;
            byte[] data = new byte[bytesRead];
            System.arraycopy(buffer, 0, data, 0, bytesRead);
            return data;
        } catch (IOException e) {
            return null;
        } finally {
            inputLock.unlock();
        }
    }

    public boolean connect() {
        // Create a TrustManager that does not validate the certificates in the tls session
        TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };

        try {
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, trustManagers, new SecureRandom());
            this.socket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
            this.inputStream = socket.getInputStream();
            this.outputStream = socket.getOutputStream();
            return connected = true;
        } catch (NoSuchAlgorithmException | IOException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean sendCell(Cell cell) {
        return write(cell.serialiseCell());
    }

    private <T> T terminated() {
        connected = false;
        return null;
    }

    public <T> T terminate() {
        connected = false;
        try {
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public <T extends Cell> T receiveNextCell() {
        int circuitId;
        byte[] circuitIdBytes = reactExact(highestSupportedVersion < 4 ? 2 : 4);
        if (circuitIdBytes == null) return terminated();
        if (circuitIdBytes.length == 2)
            circuitId = ByteBuffer.allocate(2).put(circuitIdBytes).rewind().getShort();
        else
            circuitId = ByteBuffer.allocate(4).put(circuitIdBytes).rewind().getInt();

        byte[] commandBytes = reactExact(1);
        if (commandBytes == null) return terminated();
        byte command = commandBytes[0];
        boolean fixedLengthCell = Cell.isFixedLengthCell(command);
        byte[] body = reactExact(fixedLengthCell ? Cell.FIXED_CELL_BODY_LENGTH : 2);
        if (body != null && !fixedLengthCell) {
            body = new byte[ByteBuffer.wrap(body).getShort()];
            body = reactExact(body.length);
        }
        if (body == null) return terminated();

        return Cell.parseCell(circuitId, command, body);
    }

    public boolean generalTorHandshake() {
        VersionCell clientVersions = new VersionCell(new int[]{4, 5});
        boolean success = sendCell(clientVersions);
        if (!success) return false;
        VersionCell versionCell = receiveNextCell();
        highestSupportedVersion = (byte) versionCell.highestSharedVersion(clientVersions);
        if (highestSupportedVersion == 0) return Boolean.TRUE.equals(terminate());
        CertsCell certsCell = receiveNextCell();
        if (certsCell == null) return Boolean.TRUE.equals(terminated());
        try {
            if (!certsCell.verifyCertificates(socket.getSession().getPeerCertificates()[0].getEncoded())) return Boolean.TRUE.equals(terminate());
        } catch (CertificateEncodingException | SSLPeerUnverifiedException e) {
            throw new RuntimeException(e);
        }
        AuthChallengeCell authChallengeCell = receiveNextCell();
        if (authChallengeCell == null) return Boolean.TRUE.equals(terminated());
        NetInfoCell netInfoCell = receiveNextCell();
        if (netInfoCell == null) return Boolean.TRUE.equals(terminated());
        if (netInfoCell.getAddresses().length == 0) return Boolean.TRUE.equals(terminate());

        sendCell(new NetInfoCell(new byte[4], netInfoCell.getAddresses()[0], new NetInfoCell.Address[0]));

        return true;
    }

    // Note: ConcurrentHashMap<K, V> could be used here (and probably in lots of other places) instead, but from my experience it causes more problems than it solves.
    public void addCircuit(int circuitId, Circuit circuit) {
        circuitsLock.lock();
        circuitHashMap.put(circuitId, circuit);
        circuitsLock.unlock();
    }

    public void removeCircuit(int circuitId) {
        circuitsLock.lock();
        circuitHashMap.remove(circuitId);
        circuitsLock.unlock();
    }

    public void startCellListener() {
        Thread listener = new Thread(() -> {
            while (connected) {
                Cell cell = receiveNextCell();
                if (cell == null) continue;
                try {
                    circuitsLock.lock();
                    if (!circuitHashMap.containsKey(cell.getCircuitId())) continue; // drop the cell
                    Circuit circuit = circuitHashMap.get(cell.getCircuitId());
                    if (cell instanceof DestroyCell destroyCell) {
                        circuit.destroyed(destroyCell.getReason());
                        circuitHashMap.remove(circuit.getCircuitId(), circuit);
                        continue;
                    }
                    circuit.addCell(cell);
                }
                finally {
                    circuitsLock.unlock();
                }

            }
        });
        listener.start();
    }

    public boolean isConnected() {
        return connected;
    }
}
