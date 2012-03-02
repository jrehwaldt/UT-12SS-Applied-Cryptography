package hw1;

import static hw1.MyKeyGenerator.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/*
 * Class with encryption/decryption methods.
 * 
 * You will have to implement 4 methods:
 *   - AES encryption (symmetric)
 *   - AES decryption (symmetric)
 *   - RSA encryption (asymmetric)
 *   - RSA decryption (assymetric)
 * 
 * Note that you are *not* allowed to change method signatures (adding exception,
 * changing return type, etc.) in any other ways than it is requested in the task 
 * 
 * Tasks in this file will give you 4 points.
 */
public class MyEncryptor {
	public static byte[] aesEncrypt(byte[] plaintext, SecretKey encryptionKey) {
		// FIXMEdone (1p) Implement AES encryption, replace `null` with actual ciphertext
		return aes(Cipher.ENCRYPT_MODE, plaintext, encryptionKey);
	}

	public static byte[] aesDecrypt(byte[] ciphertext, SecretKey decryptionKey) {
		// FIXMEdone (1p) Implement AES decryption, replace `null` with actual plaintext
		return aes(Cipher.DECRYPT_MODE, ciphertext, decryptionKey);
	}

	// FIXMEdone Replace Key type with a proper type from java.security.* package
	public static byte[] rsaEncrypt(byte[] plaintext, PublicKey encryptionKey) {
		// FIXMEdone (1p) Implement RSA encryption, replace `null` with actual ciphertext
		return rsa(Cipher.ENCRYPT_MODE, plaintext, encryptionKey);
	}
	
	
	// FIXMEdone Replace Key type with a proper type from java.security.* package
	public static byte[] rsaDecrypt(byte[] ciphertext, PrivateKey decryptionKey) {
		// FIXMEdone (1p) Implement RSA decryption, replace `null` with actual plaintext
		return rsa(Cipher.DECRYPT_MODE, ciphertext, decryptionKey);
	}
	
	private static byte[] aes(int opmode, byte[] data, Key key) {
		return cipher(AES_ALGORITHM, opmode, data, key, null);
	}
	
	public static byte[] rsa(int opmode, byte[] data, Key key) {
		return cipher("RSA", opmode, data, key, null);
	}
	
	public static byte[] cipher(String alg, int opmode, byte[] data, Key key, AlgorithmParameterSpec paramSpec) {
		try {
			Cipher cipher = Cipher.getInstance(alg);
			if (paramSpec != null) {
				cipher.init(opmode, key, paramSpec);
			} else {
				cipher.init(opmode, key);
			}
			return cipher.doFinal(data);
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algorithm " + "RSA" + " not available. May not occur.");
		} catch (NoSuchPaddingException e) {
			System.out.println("Padding invalid. May not occur.");
		} catch (IllegalBlockSizeException e) {
			System.out.println("Block size invalid. May not occur.");
		} catch (BadPaddingException e) {
			System.out.println("Padding invalid. May not occur.");
		} catch (InvalidKeyException e) {
			System.out.println("Key invalid. May not occur.");
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Algorithm parameter invalid. May not occur.");
			e.printStackTrace();
		}
		return null;
	}

	// Hint: you may want to use javax.crypto.Cipher class.
}
