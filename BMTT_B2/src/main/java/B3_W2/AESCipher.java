/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B3_W2;

/**
 *
 * @author roxph
 */
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class AESCipher {
    private static final String ALGORITHM = "AES";
    private static final String ENCRYPTIONKEY  = "encryptionKey";
    
    public static String encrypt(String plaintext, String secretKey)
        throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
               BadPaddingException, IllegalBlockSizeException {
    
    // Tạo khóa bí mật từ chuỗi bí mật
    SecretKey key = generateKey(secretKey);
    
    // Tạo đối tượng mã hóa
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    
    // Khởi tạo mã hóa với khóa bí mật
    cipher.init(Cipher.ENCRYPT_MODE, key);
    
    // Mã hóa chuỗi văn bản
    byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
    
    // Mã hóa Base64 và trả về kết quả
    return Base64.getEncoder().encodeToString(encryptedBytes);
    }
 /**
 * Giải mã chuỗi đã mã hóa.
 *
 * @param ciphertext Chuỗi đã mã hóa.
 * @param secretKey  Khóa bí mật.
 * @return Chuỗi giải mã.
 * @throws NoSuchAlgorithmException     Nếu thuật toán không tồn tại.
 * @throws InvalidKeyException           Nếu khóa không hợp lệ.
 * @throws NoSuchPaddingException        Nếu chế độ mã hóa không tồn tại.
 * @throws BadPaddingException           Nếu dữ liệu mã hóa không hợp lệ.
 * @throws IllegalBlockSizeException     Nếu kích thước khối không hợp lệ.
 */
    public static String decrypt(String ciphertext, String secretKey)
            throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
            BadPaddingException, IllegalBlockSizeException {

        // Tạo khóa bí mật từ chuỗi bí mật
        SecretKey key = generateKey(secretKey);

        // Tạo đối tượng mã hóa
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // Khởi tạo giải mã với khóa bí mật
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Giải mã Base64
        byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);

        // Giải mã chuỗi
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        // Trả về kết quả
        return new String(decryptedBytes);
    }

/**
 * Tạo khóa bí mật từ chuỗi bí mật.
 *
 * @param secretKey Chuỗi bí mật.
 * @return Khóa bí mật.
 * @throws NoSuchAlgorithmException Nếu thuật toán không tồn tại.
 */
    private static SecretKey generateKey(String secretKey) throws NoSuchAlgorithmException {
        // Chuyển chuỗi thành byte[]
        byte[] keyBytes = secretKey.getBytes();

        // Tạo khóa bí mật
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);

        return keySpec;
    }
    
    /**
 * Tạo khóa đăng ký từ tên người dùng và mật khẩu.
 *
 * @param username Mật khẩu người dùng
 * @param password Mật khẩu người dùng
 * @return Khóa đăng ký
 */
    public static String generateRegistrationKey(String username, String password) {
        String registrationKey = username + ":" + password + ":" + ENCRYPTIONKEY;
        return registrationKey;
    }

/**
 * Lưu khóa đăng ký vào tệp.
 *
 * @param registrationKey Khóa đăng ký
 * @param filename        Tên tệp
 * @throws IOException Nếu xảy ra lỗi I/O
 */
    public static void saveRegistrationKeyToFile(String registrationKey, String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename); ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(registrationKey);
        }
    }

/**
 * Đọc khóa đăng ký từ tệp.
 *
 * @param filename Tên tệp
 * @return Khóa đăng ký
 * @throws IOException           Nếu xảy ra lỗi I/O
 * @throws ClassNotFoundException Nếu lớp không tồn tại
 */
    public static String readRegistrationKeyFromFile(String filename) throws IOException, ClassNotFoundException {
        try (FileInputStream fis = new FileInputStream(filename); ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (String) ois.readObject();
        }
    }
}
