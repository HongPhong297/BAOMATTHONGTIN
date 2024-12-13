/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B5_W2;

/**
 *
 * @author roxph
 */
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import java.nio.charset.StandardCharsets;

public class TwofishCipher {
    private static final int BLOCK_SIZE = 16; // Twofish block size in bytes

    private BlockCipher cipher = new CBCBlockCipher(new TwofishEngine());

    /**
     * Encrypts plaintext using Twofish algorithm with CBC mode and PKCS7
     * padding.
     *
     * @param plaintext the text to be encrypted
     * @param key the encryption key
     * @param iv the initialization vector
     * @return the encrypted ciphertext
     * @throws Exception if encryption fails
     */
    public byte[] encrypt(String plaintext, byte[] key, byte[] iv) throws Exception {
        // Create padded cipher instance
        PaddedBufferedBlockCipher paddedCipher = new PaddedBufferedBlockCipher(cipher);

        // Set cipher parameters with key and IV
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);
        paddedCipher.init(true, parameters);

        // Convert plaintext to bytes
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        // Calculate minimum required buffer size
        int minSize = paddedCipher.getOutputSize(plaintextBytes.length);

        // Create output buffer
        byte[] outBuf = new byte[minSize];

        // Process plaintext bytes
        int length1 = paddedCipher.processBytes(plaintextBytes, 0, plaintextBytes.length, outBuf, 0);

        // Finalize processing
        int length2 = paddedCipher.doFinal(outBuf, length1);

        // Combine processed and finalized bytes
        byte[] ciphertext = new byte[length1 + length2];
        System.arraycopy(outBuf, 0, ciphertext, 0, ciphertext.length);

        return ciphertext;
    }
    
    /**
 * Decrypts ciphertext using Twofish algorithm with CBC mode and PKCS7 padding.
 *
 * @param ciphertext the text to be decrypted
 * @param key        the decryption key
 * @param iv         the initialization vector
 * @return the decrypted plaintext
 * @throws Exception if decryption fails
 */
    public String decrypt(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
        // Create padded cipher instance
        PaddedBufferedBlockCipher paddedCipher = new PaddedBufferedBlockCipher(cipher);

        // Set cipher parameters with key and IV
        ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);
        paddedCipher.init(false, parameters);

        // Calculate minimum required buffer size
        int minSize = paddedCipher.getOutputSize(ciphertext.length);

        // Create output buffer
        byte[] outBuf = new byte[minSize];

        // Process ciphertext bytes
        int length1 = paddedCipher.processBytes(ciphertext, 0, ciphertext.length, outBuf, 0);

        // Finalize processing
        int length2 = paddedCipher.doFinal(outBuf, length1);

        // Combine processed and finalized bytes
        byte[] plaintextBytes = new byte[length1 + length2];
        System.arraycopy(outBuf, 0, plaintextBytes, 0, length1 + length2);

        // Convert plaintext bytes to string
        return new String(plaintextBytes, 0, length1 + length2, StandardCharsets.UTF_8);
    }
}
