package hw1;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/*
 * Class with key generation methods.
 * 
 * You will have to implement AES secret key generation method. That is the trickiest task
 * of this homework. See method comments for details
 * 
 * You will also have to implement one private key pair generation method. Public methods
 * generateDsaKeyPair and generateRsaKeyPair will call it with `alg` parameter.
 * 
 * Note that you are *not* allowed to change method signatures (adding exception,
 * changing return type, etc.) in any other ways than it is requested in the task.
 * 
 * Tasks in this file will give you 6 points.
 */
public class MyKeyGenerator {

	//
	// We could normally generate the salt randomly or derive it
	// from related constant data, such as an user name
	//
	public static final byte[] SALT = "Salted. Wierd, huh?".getBytes();
	
//	Random r = new SecureRandom();
//	byte[] salt = new byte[20];
//	r.nextBytes(salt);
	
	//
	// The number of times the password will be hashed making brute forcing more difficult.
	// If a common number is used (10, 100, 1000, ...) rainbow table attacks may be performed.
	//
	// http://stackoverflow.com/questions/6126061/pbekeyspec-what-do-the-iterationcount-and-keylength-parameters-influence
	//
	public static final int ITERATION_COUNT = 22;
	public static final String AES_ALGORITHM = "PBEWITHSHA256AND128BITAES-CBC-BC";
	
	public static SecretKey generateAesSecretKey(char[] password) {
		// FIXMEdone (6p) Implement AES secret key generation, replace `null` with actual key
		
		try {
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password, SALT, ITERATION_COUNT);
			
			SecretKeyFactory factory = SecretKeyFactory.getInstance(AES_ALGORITHM);
			return factory.generateSecret(pbeKeySpec);
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algorithm " + AES_ALGORITHM + " not available. May not occur.");
		} catch (InvalidKeySpecException e) {
			System.out.println("KeySpec invalid. May not occur.");
		}
		return null;
		
		// You will have to generate a secret key based on password provided by user.
		// Note that password itself is not a key, but only one of the input parameters to
		// generate the key.
		//
		// Generating just a random key (ignoring the password) will give you 1 point.
		//
		// Generating a password-based key with default parameters will give you 3 points.
		//
		// If you will correctly use custom salt and iteration count, you will get 5 points.
		//
		// If, additionally, you will use stronger algorithms not supported by standard
		// Java Cryptography Architecture, you will get maximum of 6 points.
		//
		// This tutorial may be helpful:
		// http://www.javamex.com/tutorials/cryptography/password_based_encryption.shtml
	}

	public static KeyPair generateDsaKeyPair(int keySize) {
		return generateKeyPair("DSA", keySize);
	}

	public static KeyPair generateRsaKeyPair(int keySize) {
		return generateKeyPair("RSA", keySize);
	}

	private static KeyPair generateKeyPair(String alg, int keySize) {
		// FIXMEdone (1p) Implement key pair generation, replace `null` with actual key pair
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(alg);
			generator.initialize(keySize);
			return generator.generateKeyPair();
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algorithm " + alg + " not available. May not occur.");
		}
		return null;
	}

	// Hint: you may want to use javax.crypto.SecretKeyFactory and javax.crypto.spec.PBEKeySpec.
}
