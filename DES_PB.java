/*
 * Title: RSA encryption and SHA-1 digests
 * Author: Junkang Hu
 * Date: 30/10/2024
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.time.Instant;
import java.time.Duration;


public class DES_PB {

    private static final char[] PASSWORD = "newpassword".toCharArray();
	
    private static final byte[] SALT = { (byte)0xc7, (byte)0x73, (byte)0x21, 
                      (byte)0x8c, (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99 };  // fixed one
    private static final int ITERATION_COUNT = 2048;  // fixed one

    public static void main(String[] args) throws Exception {
        /* 
         * for loop doesn't work
         * it may be influenced by java cache strategy
         */
        // String[] texts = new String[4];
        // texts[0] = "P@S$W0rD";
        // texts[1] = "thisismypassword";
        // texts[2] = "VeryLongP@$$W0rD";
        // texts[3] = "%O^t#2Fv0JUjVdRV2RW%";

        // for (String text: texts){
        //     for (int i = 0; i < 5; i++){
        //         byte[] ciphertext = encryption(text);
        //         decryption(ciphertext);
        //         Thread.sleep(1000);
        //     }
        // }
        byte[] ciphertext = encryption("%O^t#2Fv0JUjVdRV2RW%");
        decryption(ciphertext);
        Thread.sleep(1000);
    }

    public static byte[] encryption(String text) throws Exception {
		// get input text
        System.out.println("Original: " + text);

		// encryption
        Instant en_start = Instant.now(); // check the time

        // generate a key
        PBEKeySpec keySpec = new PBEKeySpec(PASSWORD);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey pbeKey = keyFactory.generateSecret(keySpec);

        PBEParameterSpec paramSpec = new PBEParameterSpec(SALT, ITERATION_COUNT);

        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
		pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, paramSpec);

        byte[] cleartext = text.getBytes();
        byte[] ciphertext = pbeCipher.doFinal(cleartext);
		
		Instant en_end = Instant.now();
		Duration en_timegap = Duration.between(en_start, en_end);
		
		System.out.println("Encryption time cost:" + en_timegap.toNanos() + " ns");
        System.out.println("Encrypted: " + Utils.toHex(ciphertext));

        return ciphertext;
    }

    public static void decryption(byte[] ciphertext) throws Exception {
        // decryption
        Instant de_start = Instant.now(); // check the time

        // generate a key
        PBEKeySpec keySpec = new PBEKeySpec(PASSWORD);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey pbeKey = keyFactory.generateSecret(keySpec);

        PBEParameterSpec paramSpec = new PBEParameterSpec(SALT, ITERATION_COUNT);
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, paramSpec);
        
        byte[] plaintext = pbeCipher.doFinal(ciphertext);
        
        Instant de_end = Instant.now(); // check the time
        Duration de_timegap = Duration.between(de_start, de_end);
        System.out.println("Decryption time cost:" + de_timegap.toNanos() + " ns");
        String StringPlaintext = new String (plaintext);
        System.out.println("Decrypted : " + StringPlaintext);
    }
}