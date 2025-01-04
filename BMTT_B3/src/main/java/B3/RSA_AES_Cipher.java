package B3;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author roxph
 */
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

/**
 * Lớp mã hóa kết hợp RSA và AES.
 */
public class RSA_AES_Cipher {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    /**
     * Constructor.
     * 
     * @throws Exception 
     */
    public RSA_AES_Cipher() throws Exception {
        // Tạo cặp khóa RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Kích thước khóa 2048 bits
        KeyPair keyPair = keyGen.generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    /**
     * Mã hóa văn bản.
     * 
     * @param plainText Văn bản cần mã hóa.
     * @return Văn bản đã mã hóa.
     * @throws Exception 
     */
    public byte[] encrypt(String plainText) throws Exception {
        // Tạo khóa AES ngẫu nhiên
        SecretKey secretKey = generateAESKey();

        // Mã hóa khóa AES bằng RSA
        byte[] encryptedSymmetricKey = rsaEncrypt(secretKey.getEncoded());

        // Mã hóa văn bản bằng AES
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = aesCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Kết hợp khóa và dữ liệu đã mã hóa
        byte[] combined = new byte[encryptedSymmetricKey.length + encryptedData.length];
        System.arraycopy(encryptedSymmetricKey, 0, combined, 0, encryptedSymmetricKey.length);
        System.arraycopy(encryptedData, 0, combined, encryptedSymmetricKey.length, encryptedData.length);

        return combined;
    }

    // Phương thức generateAESKey() và rsaEncrypt() cần được implement
    /**
     * Giải mã văn bản.
     *
     * @param combined Dữ liệu đã mã hóa.
     * @return Văn bản đã giải mã.
     * @throws Exception
     */
    public String decrypt(byte[] combined) throws Exception {
        int symmetricKeyLength = 256;
        byte[] encryptedSymmetricKey = new byte[symmetricKeyLength];
        byte[] encryptedData = new byte[combined.length - symmetricKeyLength];

        System.arraycopy(combined, 0, encryptedSymmetricKey, 0, symmetricKeyLength);
        System.arraycopy(combined, symmetricKeyLength, encryptedData, 0, encryptedData.length);

        byte[] decryptedSymmetricKey = rsaDecrypt(encryptedSymmetricKey);
        SecretKey secretKey = new SecretKeySpec(decryptedSymmetricKey, "AES");

        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = aesCipher.doFinal(encryptedData);

        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    /**
     * Tạo khóa AES ngẫu nhiên.
     *
     * @return Khóa AES.
     * @throws NoSuchAlgorithmException
     */
    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Sử dụng AES 128
        return keyGen.generateKey();
    }

    /**
     * Mã hóa dữ liệu bằng RSA.
     *
     * @param data Dữ liệu cần mã hóa.
     * @return Dữ liệu đã mã hóa.
     * @throws Exception
     */
    private byte[] rsaEncrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * Giải mã dữ liệu bằng RSA.
     *
     * @param data Dữ liệu cần giải mã.
     * @return Dữ liệu đã giải mã.
     * @throws Exception
     */
    private byte[] rsaDecrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
    
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
