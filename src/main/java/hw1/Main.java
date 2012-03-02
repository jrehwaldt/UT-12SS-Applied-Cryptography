package hw1;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*
 * Homework #1 tasks -- read this comment carefully.
 * 
 * Homework topics: hashing, symmetric encryption, public key cryptography.
 * 
 * Here you have a code templates that you will need to modify to complete the task.
 * 
 * Main class has some methods that call other classes and methods to perform basic
 * cryptographic operations.
 * 
 * You will have to implement
 *   - several hashing methods in MyDigest class,
 *   - several key generation methods in MyKeyGenerator class,
 *   - several signing methods in MySigner class and
 *   - several encryption/decryption methods in MyEncryptor class.
 * 
 * You will also need to modify Main class a bit. You can import any classes needed.
 * 
 * Read the existing code, especially the comments. Somewhere there are useful hints explaining
 * what exactly should you do.
 * 
 * Feel free to comment out sections that are not ready yet. Do one task at a time to achieve
 * the best results. Also feel free to add you own comments to the code, as many as you like.
 * 
 * You should resolve all the issues marked with 'FIXME'. Each one gives you some points. Once
 * resolved, feel free to remove 'FIXME' comments.
 * 
 * If you cannot complete some of the sections, just comment them out. You will still receive
 * points for remaining part of the task you'll complete.
 * 
 * You are allowed to use BouncyCastle provider library, get the latest version from
 * http://www.bouncycastle.org/latest_releases.html -- you will need bcprov-jdk16-146.jar or
 * similar depending on your JVM version. Also make sure to add it to your project, example for
 * Eclipse: Project > Build Path > Configure Build Path > Libraries > Add JARs...
 * 
 * You are also allowed to use Apache Commons libraries if you feel need for that, however,
 * I recommend you do not use them here.
 * 
 * Except BC provider and Apache Commons, no other external library is allowed.
 * 
 * All together, you can get 20 points for this task.
 * 
 * Tasks in this file will give you 4 points.
 */
public class Main {
	// Choose proper key lengths here. Replace -1 with key length in bits.
	// Explain your choice in short code comments.
	//
	// The best key length is a compromise between security and fast generation time.
	// If too short or too long keys are chosen, you won't get maximum points.
	//
	// Assume that our application has no special security requirements.

	// FIXMEdone (1p) Choose the best key length for DSA, shortly explain your choice.
	//
	// 1024 is the highest possible supported.
	// NIST recommends lengths of 2048 or 3072 for security lifetime after 2010 or 2030.
	//
	private static int dsaKeySize = 1024;

	// FIXMEdone (2p) Choose the best key length for RSA, shortly explain your choice.
	//
	// Asymmetric key length 2048 is considered as being secure until around 2030.
	// Due to no special security requirements this is totally sufficient
	// for the given tasks.
	//
	private static int rsaKeySize = 2048;

	// Hint: see http://www.keylength.com/en/compare/ for ideas, use Google.



	public static void main(String[] args) throws IOException {
		// FIXMEdone (1p)
		// Import BouncyCastle provider -- you will need it to run some hashing algorithms.
		// See http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation for details.
		Security.addProvider(new BouncyCastleProvider());
		
		// For testing, file path will be provided as argument.
		// File itself will be rather small -- less than a megabyte.
		// No need to change anything here.
		String inputFilePath = args[0];
		System.out.println("File: " + inputFilePath);

		byte[] data = Util.readFile(inputFilePath);
		System.out.println("Plaintext: " + new String(data));

		// Testing hashing 
		doHashing(inputFilePath);

		// Testing signing
		doSigning(data);

		// Testing encryption
		doEncryption(data);
	}



	private static void doHashing(String inputFilePath) throws IOException {
		// Here various digest computation methods are called from MyDigest class.
		// You will have to implement those -- see MyDigest.java file for details.
		// No need to change anything here.
		System.out.println("\n> Testing hashing...");

		byte[] md5 = MyDigest.md5(new FileInputStream(inputFilePath));
		System.out.println("MD5: " + Util.toHexString(md5));

		byte[] ripemd160 = MyDigest.ripemd160(new FileInputStream(inputFilePath));
		System.out.println("RIPEMD-160: " + Util.toHexString(ripemd160));

		byte[] sha1 = MyDigest.sha1(new FileInputStream(inputFilePath));
		System.out.println("SHA-1: " + Util.toHexString(sha1));

		byte[] sha256 = MyDigest.sha256(new FileInputStream(inputFilePath));
		System.out.println("SHA-256: " + Util.toHexString(sha256));
	}



	private static void doEncryption(byte[] data) throws IOException {
		// Here various encryption/decryption methods are called from MyEncryptor class.
		// You will have to implement those -- see MyEncryptor.java file for details.
		// No need to change anything here.
		System.out.println("\n> Testing symmetric encryption...");

		String password = "MySecretPassword";
		SecretKey aesKey = MyKeyGenerator.generateAesSecretKey(password.toCharArray());
		byte[] aesCiphertext = MyEncryptor.aesEncrypt(data, aesKey);
		byte[] plaintext = MyEncryptor.aesDecrypt(aesCiphertext, aesKey);
		System.out.println("Decrypted text: " + new String(plaintext));

		System.out.println("\n> Testing public key encryption...");

		KeyPair rsaKeyPair = MyKeyGenerator.generateRsaKeyPair(rsaKeySize);
		// FIXMEdone Replace `null`-s with proper keys from rsaKeyPair
		byte[] rsaCiphertext = MyEncryptor.rsaEncrypt(data, rsaKeyPair.getPublic());
		plaintext = MyEncryptor.rsaDecrypt(rsaCiphertext, rsaKeyPair.getPrivate());
		System.out.println("Decrypted text: " + new String(plaintext));
	}



	private static void doSigning(byte[] data) throws IOException {
		// Here various digest computation methods are called from MyDigest class.
		// You will have to implement those -- see MyDigest.java file for details.
		// No need to change anything here.
		System.out.println("\n> Testing public key signatures...");

		KeyPair dsaKeyPair = MyKeyGenerator.generateDsaKeyPair(dsaKeySize);
		// FIXMEdone Replace `null`-s with proper keys from dsaKeyPair
		byte[] dsaSig = MySigner.dsaSign(data, dsaKeyPair.getPrivate());
		boolean dsaVerificationResult = MySigner.dsaVerify(data, dsaSig, dsaKeyPair.getPublic());
		System.out.println("DSA signature verified: " + dsaVerificationResult);

		KeyPair rsaKeyPair = MyKeyGenerator.generateRsaKeyPair(rsaKeySize);
		// FIXMEdone Replace `null`-s with proper keys from rsaKeyPair
		byte[] rsaSig = MySigner.rsaSign(data, rsaKeyPair.getPrivate());
		boolean rsaVerificationResult = MySigner.rsaVerify(data, rsaSig, rsaKeyPair.getPublic());
		System.out.println("RSA signature verified: " + rsaVerificationResult);
	}
}
