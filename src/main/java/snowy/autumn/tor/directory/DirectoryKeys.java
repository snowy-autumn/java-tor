package snowy.autumn.tor.directory;

import snowy.autumn.tor.directory.documents.DirectoryKeyNetDoc;

import java.util.HashMap;
import java.util.HexFormat;

public class DirectoryKeys {

    HashMap<String, DirectoryKeyNetDoc> directoryKeyNetDocHashMap = new HashMap<>();

    private static String hex(byte[] input) {
        return HexFormat.of().formatHex(input).toLowerCase();
    }

    public DirectoryKeys(DirectoryKeyNetDoc[] directoryKeyCerts) {
        for (DirectoryKeyNetDoc directoryKeyNetDoc : directoryKeyCerts) {
            directoryKeyNetDocHashMap.put(hex(directoryKeyNetDoc.getFingerprint()), directoryKeyNetDoc);
        }
    }

    public DirectoryKeyNetDoc getDirectoryKeys(byte[] fingerprint) {
        return getDirectoryKeys(hex(fingerprint));
    }

    public DirectoryKeyNetDoc getDirectoryKeys(String fingerprint) {
        return directoryKeyNetDocHashMap.get(fingerprint.toLowerCase());
    }

    public int getDirectoryCount() {
        return directoryKeyNetDocHashMap.size();
    }

}
