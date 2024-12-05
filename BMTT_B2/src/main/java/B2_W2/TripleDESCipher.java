/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B2_W2;

/**
 *
 * @author roxph
 */
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
public class TripleDESCipher {
    private static final String ALGORITHM = "DESede";
    public static String encrypt(String plaintext, String secretKey)
            throws NoSuchAlgorithmException,
            InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        SecretKey key = generateKey(secretKey);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    
    
    public static String decrypt(String ciphertext, String secretKey)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        SecretKey key = generateKey(secretKey);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }
    
    
    
    private static SecretKey generateKey(String secretKey) throws NoSuchAlgorithmException {
    // Key must be 24 bytes (192 bits) long for Triple DES
    byte[] keyBytes = secretKey.getBytes();
    byte[] validKeyBytes = new byte[24];
    
    // Truncate or pad keyBytes to make it 24 bytes long
    for (int i = 0; i < validKeyBytes.length; i++) {
        if (i < keyBytes.length) {
            validKeyBytes[i] = keyBytes[i];
        } else {
            validKeyBytes[i] = 0;  // or any other value as padding
        }
    }
    
    // Create a SecretKeySpec with the valid 24-byte key
    SecretKeySpec keySpec = new SecretKeySpec(validKeyBytes, ALGORITHM);
    
    return keySpec;
    
    }

}
