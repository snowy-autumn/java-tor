package snowy.autumn.tor.maths;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Ed25519 {

    public static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    public static final BigInteger D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    public static final BigInteger L = BigInteger.TWO.pow(252).add(new BigInteger("27742317777372353535851937790883648493"));

    private static byte[] reverseByteArray(byte[] array) {
        byte[] reversed = new byte[array.length];
        for (int i = 0; i < reversed.length; i++) {
            reversed[i] = array[array.length - i - 1];
        }
        return reversed;
    }

    public static BigInteger littleEndianBigInteger(byte[] bytes) {
        return new BigInteger(reverseByteArray(bytes));
    }

    public static class Point {
        BigInteger x;
        BigInteger y;

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        private static Point identity() {
            // For this specifically I prefer to use valueOf instead of BigInteger.ZERO or BigInteger.ONE
            return new Point(BigInteger.valueOf(0), BigInteger.valueOf(1));
        }

        public void scalarMultiplication(byte[] scalar) {
            Point point = Ed25519.scalarMultiplication(this, littleEndianBigInteger(scalar));
            this.x = point.x;
            this.y = point.y;
        }

        public byte[] compress() {
            byte[] publicKey = reverseByteArray(y.toByteArray());

            // Note: This should only happen when the public key is of size 31. If the size is neither 31 nor 32, then something very strange has happened.
            if (publicKey.length != 32)
                publicKey = ByteBuffer.allocate(32).put(publicKey).array();

            // Probably don't need to clear that bit, but it can't hurt.
            publicKey[31] &= 0x7F;
            publicKey[31] |= (byte) ((x.testBit(0) ? 1 : 0) << 7);

            return publicKey;
        }
    }

    public record Ed25519PublicKeyProperties(BigInteger y, byte xSign) {}

    private static Ed25519PublicKeyProperties extractYnXSign(byte[] publicKey) {
        byte sign = (byte) ((publicKey[31] >> 7) & 1);
        byte[] y = reverseByteArray(publicKey);
        y[0] &= 0x7F;

        return new Ed25519PublicKeyProperties(new BigInteger(y), sign);
    }

    public static Point decompress(byte[] publicKey) {
        Ed25519PublicKeyProperties properties = extractYnXSign(publicKey);
        BigInteger ySquared = properties.y().pow(2);
        BigInteger xSquared = ySquared.subtract(BigInteger.ONE).multiply(
                ySquared.multiply(D).add(BigInteger.ONE).modInverse(P)
        ).mod(P);
        // We can't just use sqrt, since we're working within a finite field.
        BigInteger x = xSquared.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P);
        if (x.pow(2).subtract(xSquared).mod(P).compareTo(BigInteger.ZERO) != 0)
            x = x.multiply(BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)).mod(P);

        if (x.mod(BigInteger.TWO).compareTo(BigInteger.valueOf(properties.xSign())) != 0)
            x = P.subtract(x);

        return new Point(x, properties.y());
    }

    private static Point addEdwards25519Points(Point a, Point b) {
        BigInteger aXbY = a.x.multiply(b.y);
        BigInteger bXaY = b.x.multiply(a.y);
        BigInteger dAB = D.multiply(aXbY).multiply(bXaY);

        BigInteger x = aXbY.add(bXaY).multiply(BigInteger.ONE.add(dAB).modInverse(P)).mod(P);

        // Saw some places saying this should be subtraction instead of addition, but addition works so..
        BigInteger y = a.y.multiply(b.y).add(a.x.multiply(b.x)).multiply(BigInteger.ONE.subtract(dAB).modInverse(P)).mod(P);

        return new Point(x, y);
    }

    public static Point scalarMultiplication(Point point, BigInteger scalar) {
        if (scalar.compareTo(BigInteger.ZERO) == 0) return Point.identity();

        Point newPoint = scalarMultiplication(point, scalar.divide(BigInteger.TWO));
        newPoint = addEdwards25519Points(newPoint, newPoint);

        if (scalar.testBit(0))
            newPoint = addEdwards25519Points(newPoint, point);

        return newPoint;
    }

    private static byte[] reduce(byte[] scalar) {
        return reverseByteArray(littleEndianBigInteger(scalar).mod(L).toByteArray());
    }

    public static byte[] clampPrivateKey(byte[] scalar) {
        scalar[0] &= -8;
        scalar[31] &= 63;
        scalar[31] |= 64;
        return reduce(scalar);
    }

}
