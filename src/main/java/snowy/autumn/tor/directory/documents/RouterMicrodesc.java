package snowy.autumn.tor.directory.documents;

public record RouterMicrodesc(String host, int port, byte[] fingerprint, String microdescHash) {

}
