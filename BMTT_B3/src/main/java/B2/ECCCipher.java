package B2;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author roxph
 */
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

/**
 * Lớp thực hiện mã hóa và giải mã sử dụng thuật toán ECC.
 */
public class ECCCipher {

    private static final String EC_ALGORITHM = "EC";
    private static final String ECC_CIPHER_ALGORITHM = "ECIES";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Tạo cặp khóa công khai và riêng tư.
     * 
     * @return Cặp khóa.
     * @throws NoSuchAlgorithmException 
     * @throws InvalidAlgorithmParameterException 
     * @throws NoSuchProviderException 
     */
    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGORITHM, "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }
    
    
    /**
 * Mã hóa văn bản sử dụng khóa công khai.
     *
     * @param plaintext Văn bản cần mã hóa.
     * @param publicKey Khóa công khai.
     * @return Văn bản đã mã hóa.
     * @throws Exception
     */
    public byte[] encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ECC_CIPHER_ALGORITHM, "BC");
        byte[] nonce = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        IESParameterSpec params = new IESParameterSpec(null, null, 128, 128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, params);
        return cipher.doFinal(plaintext.getBytes());
    }

    /**
     * Giải mã văn bản sử dụng khóa riêng tư.
     *
     * @param ciphertext Văn bản đã mã hóa.
     * @param privateKey Khóa riêng tư.
     * @return Văn bản đã giải mã.
     * @throws Exception
     */
/**
 * Giải mã văn bản sử dụng khóa riêng tư.
 * 
 * @param ciphertext Văn bản đã mã hóa.
 * @param privateKey  Khóa riêng tư.
 * @return Văn bản đã giải mã.
 * @throws Exception 
 */
    public String decrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ECC_CIPHER_ALGORITHM, "BC");

        // Sử dụng nonce từ văn bản mã hóa
        byte[] nonce = new byte[16];
        
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
//        System.arraycopy(ciphertext, 0, nonce, 0, 16);

        IESParameterSpec params = new IESParameterSpec(null, null, 128, 128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, params);

        // Giải mã từ offset 16
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes);
    }

    /**
     * Tải khóa công khai từ byte array.
     *
     * @param keyBytes Byte array chứa khóa công khai.
     * @return Khóa công khai.
     * @throws Exception
     */
    public static PublicKey loadPublicKey(byte[] keyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, "BC");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * Tải khóa riêng tư từ byte array.
     *
     * @param keyBytes Byte array chứa khóa riêng tư.
     * @return Khóa riêng tư.
     * @throws Exception
     */
    public static PrivateKey loadPrivateKey(byte[] keyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, "BC");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
