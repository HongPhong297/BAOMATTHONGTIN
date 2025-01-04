/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B1;

/**
 *
 * @author roxph
 */
import java.math.BigInteger;
import java.util.Random;

/**
 * RSA Cipher implementation.
 */
public class RSACipher {

    private BigInteger p, q, N, phiN, e, d;
    private int bitLength;

    /**
     * Constructor.
     * 
     * @param bitLength Key size in bits.
     */
    public RSACipher(int bitLength) {
        this.bitLength = bitLength;
        generateKeys();
    }

    /**
     * Generates RSA keys.
     */
    private void generateKeys() {
        p = BigInteger.probablePrime(bitLength / 2, new Random());
        q = BigInteger.probablePrime(bitLength / 2, new Random());

        N = p.multiply(q);
        phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        do {
            e = new BigInteger(bitLength, new Random());
        } while ((e.compareTo(phiN) != -1) || (e.gcd(phiN).compareTo(BigInteger.ONE) != 0));

        d = e.modInverse(phiN);
    }

    /**
     * Encrypts a message using RSA.
     * 
     * @param message Message to encrypt.
     * @return Encrypted message.
     */
    public BigInteger[] encrypt(String message) {
        byte[] bytes = message.getBytes();
        BigInteger[] encrypted = new BigInteger[bytes.length];

        for (int i = 0; i < bytes.length; i++) {
            encrypted[i] = new BigInteger(new byte[] { bytes[i] }).modPow(e, N);
        }

        return encrypted;
    }
    /**
     * Decrypts an RSA-encrypted message.
     *
     * @param message Encrypted message.
     * @param d Private key.
     * @param n Modulus.
     * @return Decrypted message.
     */
    public String decrypt(BigInteger[] message, BigInteger d, BigInteger n) {
        byte[] bytes = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            bytes[i] = message[i].modPow(d, n).byteValue();
        }
        return new String(bytes);
    }

    /**
     * Getters for RSA key components.
     */
    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getN() {
        return N;
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getD() {
        return d;
    }
}