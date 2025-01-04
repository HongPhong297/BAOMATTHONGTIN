/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package B1;

/**
 *
 * @author roxph
 */
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Util {

    public static String md5(String input) {
        try {
            // Get an instance of the MD5 message digest algorithm
            MessageDigest md = MessageDigest.getInstance("MD5");
            
            // Update the digest with the input bytes
            md.update(input.getBytes());
            
            // Compute the hash
            byte[] digest = md.digest();
            
            // Convert the byte array to a BigInteger
            BigInteger bigInt = new BigInteger(1, digest);
            
            // Convert the BigInteger to a hexadecimal string
            String md5Hex = bigInt.toString(16);
            
            // Pad the string with leading zeros to ensure it is 32 characters long
            while (md5Hex.length() < 32) {
                md5Hex = "0" + md5Hex;
            }
            
            return md5Hex;
        } catch (NoSuchAlgorithmException e) {
            // Handle the case where the MD5 algorithm is not available
            e.printStackTrace();
            return null;
        }
    }
}
