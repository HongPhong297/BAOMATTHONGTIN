/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B5;

/**
 *
 * @author roxph
 */
import java.util.Arrays;

public class TranspositionCipher {

    private int d; // Kích thước khối
    private int[] f; // Hoán vị của khối

    // Constructor nhận d và f
    public TranspositionCipher(int d, int[] f) {
        if (f.length != d) {
            throw new IllegalArgumentException("Chiều dài của hoán vị f phải bằng d.");
        }
        this.d = d;
        this.f = f.clone(); // Sao chép mảng để đảm bảo an toàn dữ liệu
    }

    // Mã hóa văn bản
    public String encrypt(String plaintext) {
        plaintext = plaintext.replaceAll("\\s", ""); // Loại bỏ khoảng trắng
        int n = plaintext.length();
        int padding = d - (n % d); // Số ký tự cần đệm để đủ khối
        if (padding != d) {
            char[] paddingChars = new char[padding];
            Arrays.fill(paddingChars, 'X'); // Điền ký tự 'X' để đệm
            plaintext += new String(paddingChars);
        }

        StringBuilder ciphertext = new StringBuilder();

        // Xử lý từng khối
        for (int i = 0; i < plaintext.length(); i += d) {
            char[] block = plaintext.substring(i, i + d).toCharArray();
            char[] permutedBlock = new char[d];

            // Áp dụng hoán vị f
            for (int j = 0; j < d; j++) {
                permutedBlock[j] = block[f[j] - 1]; // f[j] là vị trí 1-based
            }

            ciphertext.append(permutedBlock);
        }

        return ciphertext.toString();
    }
    

    // Giải mã văn bản
    public String decrypt(String ciphertext) {
        int n = ciphertext.length();
        StringBuilder plaintext = new StringBuilder();

        // Tính toán hoán vị ngược
        int[] inverseF = new int[d];
        for (int i = 0; i < d; i++) {
            inverseF[f[i] - 1] = i + 1; // Tạo hoán vị ngược (1-based)
        }

        // Xử lý từng khối
        for (int i = 0; i < n; i += d) {
            char[] block = ciphertext.substring(i, i + d).toCharArray();
            char[] originalBlock = new char[d];

            // Áp dụng hoán vị ngược
            for (int j = 0; j < d; j++) {
                originalBlock[j] = block[inverseF[j] - 1]; // inverseF[j] là vị trí 1-based
            }

            plaintext.append(originalBlock);
        }

        return plaintext.toString().replaceAll("X+$", ""); // Loại bỏ ký tự đệm
    }

//    // Main để kiểm tra
//    public static void main(String[] args) {
//        int d = 5;
//        int[] f = {3, 5, 1, 4, 2}; // Hoán vị của dãy 12345
//
//        TranspositionCipher cipher = new TranspositionCipher(d, f);
//
//        String plaintext = "HELLOTHISISATEST";
//        System.out.println("Plaintext: " + plaintext);
//
//        String encrypted = cipher.encrypt(plaintext);
//        System.out.println("Encrypted: " + encrypted);
//
//        String decrypted = cipher.decrypt(encrypted);
//        System.out.println("Decrypted: " + decrypted);
//    }
}

