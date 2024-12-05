/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B2;

/**
 *
 * @author Administrator
 */

public class VigenereCipher {

    public static String encrypt(String text, String key) {
        return vigenereCipher(text, key, true);
    }

    public static String decrypt(String text, String key) {
        return vigenereCipher(text, key, false);
    }

    private static String vigenereCipher(String text, String key, boolean encrypt) {
        StringBuilder result = new StringBuilder();
        key = key.toLowerCase();
        int keyLength = key.length();
        int keyIndex = 0;

        for (char character : text.toCharArray()) {
            if (Character.isLetter(character)) {
                char base = Character.isUpperCase(character) ? 'A' : 'a';
                int shift = key.charAt(keyIndex % keyLength) - 'a';
                if (!encrypt) {
                    shift = 26 - shift;
                }

                result.append((char) ((character - base + shift) % 26 + base));
                keyIndex++;
            } else {
                result.append(character);
            }
        }

        return result.toString();
    }
}

