package snowy.autumn.tor.hs;

import org.bouncycastle.util.encoders.Base32;
import snowy.autumn.tor.crypto.Cryptography;
import snowy.autumn.tor.maths.Ed25519;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

public class OnionAddress {

    public static final byte[] BLIND_STRING = "Derive temporary signing key\0".getBytes();
    public static final byte[] ED25519_BASEPOINT = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)".getBytes();

    String address;
    byte[] publicKey = new byte[32];
    short checksum;
    byte version;

    byte[] N_hs_credential;

    MessageDigest sha3_256 = Cryptography.createDigest("SHA3-256");

    public OnionAddress(String address) {
        if (!address.endsWith(".onion"))
            // Note: This is a terrible idea, since websites can usually make the browser attempt to redirect TOR users to a hidden service version of themselves.
            // By throwing an error for every malformed address, a bad actor can essentially send bad addresses in order to crash the client.
            // But since this is just an insignificant attempt at a client and this implementation is only temporary, I guess we can ignore it for now.
            throw new Error("Invalid onion address: " + address);
        else if (address.length() != 62) throw new Error("Potentially unsupported hidden service version: " + address); // Again, terrible idea.
        this.address = address.toLowerCase();

        ByteBuffer buffer = ByteBuffer.wrap(Base32.decode(address.substring(0, address.lastIndexOf(".onion")).toUpperCase()));
        buffer.get(publicKey);
        checksum = buffer.getShort();
        version = buffer.get();
        if (version != 3) throw new Error("Potentially unsupported version of hidden service: " + address); // You get the point, terrible idea.
        short calculatedChecksum = ByteBuffer.wrap(sha3_256.digest(ByteBuffer.allocate(15 + 32 + 1)
                .put(".onion checksum".getBytes())
                .put(publicKey)
                .put(version).array())).getShort();

        if (checksum != calculatedChecksum) throw new Error("Checksums do not match for hidden service address: " + address + ", calculated checksum: " + calculatedChecksum + ", embedded checksum: " + checksum);

        N_hs_credential = sha3_256.digest(ByteBuffer.allocate(10 + 32).put("credential".getBytes()).put(publicKey).array());
    }

    // This method is private since even arti doesn't use 'secret', and so it's likely that most people will not need access to it.
    private byte[] calculateBlindingFactor(byte[] secret) {
        MessageDigest sha3_256 = Cryptography.createDigest("SHA3-256");
        sha3_256.update(BLIND_STRING);
        sha3_256.update(publicKey);
        sha3_256.update(secret);
        sha3_256.update(ED25519_BASEPOINT);
        sha3_256.update("key-blind".getBytes());
        sha3_256.update(ByteBuffer.allocate(8).putLong(HiddenService.getCurrentTimePeriod()).array());
        sha3_256.update(ByteBuffer.allocate(8).putLong(HiddenService.getPeriodLength()).array());
        return sha3_256.digest();
    }

    /**
     Calculates the blinded public key. Assumes that 'secret' is a nonce, as mentioned in the comment for {@link #calculateBlindingFactor(byte[] secret)}
     **/
    public byte[] blindedPublicKey() {
        // Calculate the blinding factor for the current period.
        byte[] blindingFactor = calculateBlindingFactor(new byte[0]);
        // Clamps the blinding factor as if it were an Ed25519 private key.
        blindingFactor = Ed25519.clampPrivateKey(blindingFactor);

        // Decompress the onion service's public key as if it into a point on the Edwards25519 curve.
        Ed25519.Point publicKeyPoint = Ed25519.decompress(publicKey);
        // Multiplies the public key point by the blinding factor.
        publicKeyPoint.scalarMultiplication(blindingFactor);

        // return the point compressed back into an Ed25519 public key.
        return publicKeyPoint.compress();
    }

    // Calculates the subcredential for the current period.
    public byte[] N_hs_subcredential() {
        MessageDigest sha3_256 = Cryptography.createDigest("SHA3-256");
        sha3_256.update("subcredential".getBytes());
        sha3_256.update(N_hs_credential);
        sha3_256.update(blindedPublicKey());
        return sha3_256.digest();
    }

}
