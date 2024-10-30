/*
 * Title: RSA encryption and SHA-1 digests
 * Author: Junkang Hu
 * Date: 30/10/2024
 */

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import java.security.Security;

import java.security.MessageDigest;

import java.util.HashMap;
import java.util.Arrays;


public class RSA_SHA1 {
    public static void main(String[] args) throws Exception
    {
        String input = System.console().readLine("enter your message: ");
        HashMap<String, Object> message = encryption(input);

        System.out.println(message);

        decryption(message);

    }
    
    public static HashMap<String, Object> encryption(String input) throws Exception{
        // calculates the hash value of input text
        MessageDigest hash = MessageDigest.getInstance("SHA1");
        hash.update(Utils.toByteArray(input));

        // generates a key pair by RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(512, random);

        KeyPair pair = generator.generateKeyPair();
        Key public_key = pair.getPublic();
        Key private_key = pair.getPrivate();

        // encryption via private key
        cipher.init(Cipher.ENCRYPT_MODE, private_key);
        byte[] ciphertext = cipher.doFinal(hash.digest());

        // send message
        HashMap<String, Object> en_message = new HashMap<>();
        en_message.put("original_message", input);
        en_message.put("encrypted_digest", ciphertext);
        en_message.put("public_key", public_key);

        return en_message;
    }

    public static void decryption(HashMap<String, Object> message) throws Exception {
        Key public_key = (Key) message.get("public_key");

        // generates a key pair by RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, public_key);
        // decryption
        byte[] endigest = (byte[]) message.get("encrypted_digest");
        byte[] digest = cipher.doFinal(endigest);

        // Compute the hash of the original message
        String original_message = (String) message.get("original_message");
        MessageDigest hash = MessageDigest.getInstance("SHA-1");
        hash.update(original_message.getBytes());

        // compare digests
        System.out.println(message.get("encrypted_digest"));
        System.out.println(hash.digest());
        System.out.println("Comparison with them: " + Arrays.equals(hash.digest(), digest));
    }
}
