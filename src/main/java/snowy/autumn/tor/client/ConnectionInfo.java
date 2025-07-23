package snowy.autumn.tor.client;

import snowy.autumn.tor.circuit.Circuit;

public class ConnectionInfo {

	ConnectionIO connectionIO;
	byte status;

	public ConnectionInfo(ConnectionIO connectionIO, byte status) {
		this.connectionIO = connectionIO;
		this.status = status;
	}

	public boolean isConnected() {
		return connectionIO != null && status == Circuit.STREAM_SUCCESSFUL;
	}

	public ConnectionIO getConnectionIO() {
		return connectionIO;
	}

	public byte getStatus() {
		return status;
	}

}
