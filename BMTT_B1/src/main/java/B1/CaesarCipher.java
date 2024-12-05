/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B1;

/**
 *
 * @author Administrator
 */
public class CaesarCipher {
    public static String encypt(String text, int key) {
        return caesarCipher(text, key, true);
    }
    
    public static String decrypt(String text, int key) {
        return caesarCipher(text, key, false);
    }
    private static String caesarCipher(String text, int key, boolean encrypt) {
        StringBuilder result = new StringBuilder();
        int shift = encrypt ? key : -key;
        
        for (char character : text.toCharArray()) {
            if(Character.isLetter(character)) {
                char base = Character.isUpperCase(character) ? 'A' : 'a';
                int offset = (character - base + shift) % 26;
                if (offset < 0) {
                    offset += 26;
                }
                result.append((char)(base + offset));
                
            } else {
                result.append(character);
            }   
            
        }
        
        return result.toString();
    }
}
