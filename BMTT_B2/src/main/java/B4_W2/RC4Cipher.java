/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B4_W2;

/**
 *
 * @author roxph
 */

public class RC4Cipher {
    private byte[] S = new byte[256];
    private byte[] T = new byte[256];
    private int keylen;
    /**
 * Khởi tạo mã hóa RC4 với khóa bí mật.
 *
 * @param key Khóa bí mật dưới dạng mảng byte
 */
    public RC4Cipher(byte[] key) {
        // Lưu chiều dài khóa
        keylen = key.length;

        // Khởi tạo mảng S và T
        for (int i = 0; i < 256; i++) {
            S[i] = (byte) i;
            T[i] = key[i % keylen];
        }

        // Thực hiện hoán đổi ban đầu
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + S[i] + T[i]) & 0xFF;
            swap(S, i, j);
        }
    }

    /**
     * Hoán đổi hai phần tử trong mảng.
     *
     * @param arr Mảng cần hoán đổi
     * @param i Chỉ số phần tử thứ nhất
     * @param j Chỉ số phần tử thứ hai
     */
    private void swap(byte[] arr, int i, int j) {
        byte temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
    
    /**
 * Mã hóa văn bản bằng thuật toán RC4.
 *
 * @param plaintext Văn bản cần mã hóa
 * @return Văn bản đã mã hóa
 */
    public byte[] encrypt(byte[] plaintext) {
        // Tạo mảng lưu văn bản đã mã hóa
        byte[] ciphertext = new byte[plaintext.length];

        // Khởi tạo biến chỉ số
        int i = 0, j = 0;

        // Mã hóa từng byte
        for (int k = 0; k < plaintext.length; k++) {
            // Cập nhật chỉ số
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;

            // Hoán đổi phần tử trong mảng S
            swap(S, i, j);

            // Tính chỉ số phần tử trong mảng S
            int t = (S[i] + S[j]) & 0xFF;

            // Mã hóa byte hiện tại
            ciphertext[k] = (byte) (plaintext[k] ^ S[t]);
        }

        return ciphertext;
    }

    /**
     * Giải mã văn bản bằng thuật toán RC4.
     *
     * @param ciphertext Văn bản đã mã hóa
     * @return Văn bản giải mã
     */
    public byte[] decrypt(byte[] ciphertext) {
        // RC4 có tính đối xứng, nên sử dụng hàm encrypt để giải mã
        return encrypt(ciphertext);
    }
}
