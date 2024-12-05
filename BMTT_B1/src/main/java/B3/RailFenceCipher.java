/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B3;

/**
 *
 * @author roxphong@gmail.com
 */


public class RailFenceCipher {

    public static String encrypt(String text, int key) {
        if (key <= 1) {
            return text;
        }

        char[] chars = text.toCharArray();
        char[] result = new char[chars.length];
        int cycle = 2 * key - 2;
        int idx = 0;

        for (int i = 0; i < key; i++) {
            for (int j = 0; j + i < chars.length; j += cycle) {
                result[idx++] = chars[i + j];
                if (i != 0 && i != key - 1 && j + cycle - i < chars.length) {
                    result[idx++] = chars[j + cycle - i];
                }
            }
        }

        return new String(result);
    }

    public static String decrypt(String text, int key) {
        if (key <= 1) {
            return text;
        }

        char[] chars = text.toCharArray();
        char[] result = new char[chars.length];
        int cycle = 2 * key - 2;
        int idx = 0;

        for (int i = 0; i < key; i++) {
            for (int j = 0; j + i < chars.length; j += cycle) {
                result[i + j] = chars[idx++];
                if (i != 0 && i != key - 1 && j + cycle - i < chars.length) {
                    result[j + cycle - i] = chars[idx++];
                }
            }
        }

        return new String(result);
    }
}

