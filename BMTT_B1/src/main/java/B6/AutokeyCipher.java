/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B6;

/**
 *
 * @author roxph
 */
public class AutokeyCipher {

    private String key; // Khóa ban đầu

    // Constructor nhận khóa
    public AutokeyCipher(String key) {
        this.key = key.toUpperCase(); // Chuyển khóa về chữ hoa
    }

    // Phương thức mã hóa
    public String encrypt(String plaintext) {
        plaintext = plaintext.toUpperCase().replaceAll("[^A-Z]", ""); // Chỉ giữ lại chữ cái
        StringBuilder extendedKey = new StringBuilder(key);

        // Mở rộng khóa bằng cách thêm bản rõ vào sau khóa ban đầu
        while (extendedKey.length() < plaintext.length()) {
            extendedKey.append(plaintext);
        }

        StringBuilder ciphertext = new StringBuilder();

        // Mã hóa từng ký tự
        for (int i = 0; i < plaintext.length(); i++) {
            char p = plaintext.charAt(i);
            char k = extendedKey.charAt(i);
            char c = (char) ((p - 'A' + k - 'A') % 26 + 'A'); // Phép cộng modulo 26
            ciphertext.append(c);
        }

        return ciphertext.toString();
    }

    // Phương thức giải mã
    public String decrypt(String ciphertext) {
        ciphertext = ciphertext.toUpperCase().replaceAll("[^A-Z]", ""); // Chỉ giữ lại chữ cái
        StringBuilder extendedKey = new StringBuilder(key);
        StringBuilder plaintext = new StringBuilder();

        // Giải mã từng ký tự
        for (int i = 0; i < ciphertext.length(); i++) {
            char c = ciphertext.charAt(i);
            char k = extendedKey.charAt(i);
            char p = (char) ((c - k + 26) % 26 + 'A'); // Phép trừ modulo 26
            plaintext.append(p);

            // Mở rộng khóa bằng ký tự vừa giải mã
            extendedKey.append(p);
        }

        return plaintext.toString();
    }

    // Main để kiểm tra
//    public static void main(String[] args) {
//        String key = "LEMON";
//        String plaintext = "ATTACKATDAWN";
//
//        AutokeyCipher cipher = new AutokeyCipher(key);
//
//        System.out.println("Plaintext: " + plaintext);
//
//        // Mã hóa
//        String encrypted = cipher.encrypt(plaintext);
//        System.out.println("Encrypted: " + encrypted);
//
//        // Giải mã
//        String decrypted = cipher.decrypt(encrypted);
//        System.out.println("Decrypted: " + decrypted);
//    }
}
