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
            // Todo: Instead of doing this, the client should just be able to automatically refetch the authority key certs.
            if (!directoryKeyNetDoc.isValid()) throw new RuntimeException("Directory key certs for fingerprint '" + HexFormat.of().formatHex(directoryKeyNetDoc.getFingerprint()) + "' are invalid.");
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

    public DirectoryKeyNetDoc[] getDirectoryKeyNetDocs() {
        return directoryKeyNetDocHashMap.values().toArray(new DirectoryKeyNetDoc[0]);
    }

    public boolean allValid() {
        return directoryKeyNetDocHashMap.values().stream().allMatch(DirectoryKeyNetDoc::isValid);
    }
}
