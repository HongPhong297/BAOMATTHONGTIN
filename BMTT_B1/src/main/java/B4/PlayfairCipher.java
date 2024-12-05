/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B4;



public class PlayfairCipher {

    private char[][] table;

    // Constructor tạo bảng Playfair từ khóa
    public PlayfairCipher(String key) {
        generateTable(key);
    }

    // Tạo bảng Playfair từ khóa
    private void generateTable(String key) {
        key = key.toUpperCase().replaceAll("[^A-Z]", "").replace('J', 'I');
        boolean[] used = new boolean[26];
        table = new char[5][5];
        int index = 0;

        for (char c : key.toCharArray()) {
            if (!used[c - 'A']) {
                table[index / 5][index % 5] = c;
                used[c - 'A'] = true;
                index++;
            }
        }

        for (char c = 'A'; c <= 'Z'; c++) {
            if (c == 'J') continue; // J được thay bằng I
            if (!used[c - 'A']) {
                table[index / 5][index % 5] = c;
                used[c - 'A'] = true;
                index++;
            }
        }
    }

    // Mã hóa văn bản
    public String encrypt(String plaintext) {
        plaintext = preprocess(plaintext);
        return processText(plaintext, true);
    }

    // Giải mã văn bản
    public String decrypt(String ciphertext) {
        return processText(ciphertext, false);
    }

    // Xử lý văn bản (mã hóa/giải mã)
    private String processText(String text, boolean encrypt) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < text.length(); i += 2) {
            char a = text.charAt(i);
            char b = text.charAt(i + 1);
            int[] posA = findPosition(a);
            int[] posB = findPosition(b);

            if (posA[0] == posB[0]) { // Cùng hàng
                result.append(table[posA[0]][(posA[1] + (encrypt ? 1 : 4)) % 5]);
                result.append(table[posB[0]][(posB[1] + (encrypt ? 1 : 4)) % 5]);
            } else if (posA[1] == posB[1]) { // Cùng cột
                result.append(table[(posA[0] + (encrypt ? 1 : 4)) % 5][posA[1]]);
                result.append(table[(posB[0] + (encrypt ? 1 : 4)) % 5][posB[1]]);
            } else { // Khác hàng, khác cột
                result.append(table[posA[0]][posB[1]]);
                result.append(table[posB[0]][posA[1]]);
            }
        }

        return result.toString();
    }

    // Tìm vị trí của ký tự trong bảng Playfair
    private int[] findPosition(char c) {
        for (int row = 0; row < 5; row++) {
            for (int col = 0; col < 5; col++) {
                if (table[row][col] == c) {
                    return new int[]{row, col};
                }
            }
        }
        return null; // Không xảy ra nếu c tồn tại trong bảng
    }

    // Tiền xử lý văn bản gốc
    private String preprocess(String text) {
        text = text.toUpperCase().replaceAll("[^A-Z]", "").replace('J', 'I');
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            char current = text.charAt(i);
            if (i < text.length() - 1 && current == text.charAt(i + 1)) {
                result.append(current).append('X'); // Thêm X khi hai ký tự trùng
            } else {
                result.append(current);
            }
        }

        if (result.length() % 2 != 0) {
            result.append('X'); // Thêm X nếu độ dài lẻ
        }

        return result.toString();
    }

    // In bảng Playfair
    // Trả về bảng Playfair dưới dạng chuỗi
    public String getTableAsString() {
        StringBuilder builder = new StringBuilder();
        for (int row = 0; row < 5; row++) {
            for (int col = 0; col < 5; col++) {
                builder.append(table[row][col]).append(" ");
            }
            builder.append("\n"); // Xuống dòng sau mỗi hàng
        }
        return builder.toString();
    }


    // Main để kiểm tra
//    public static void main(String[] args) {
//        String key = "PLAYFAIR";
//        String plaintext = "HELLO WORLD";
//
//        PlayfairCipher cipher = new PlayfairCipher(key);
//
//        System.out.println("Bảng Playfair:");
//        cipher.printTable();
//
//        String encrypted = cipher.encrypt(plaintext);
//        System.out.println("Văn bản mã hóa: " + encrypted);
//
//        String decrypted = cipher.decrypt(encrypted);
//        System.out.println("Văn bản giải mã: " + decrypted);
//    }
}
