package hw1;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/*
 * Class with signing and signature verification methods.
 * 
 * You will have to implement 4 methods:
 *   - DSA signing
 *   - DSA verification
 *   - RSA signing
 *   - RSA verification
 * 
 * Note that you are *not* allowed to change method signatures (adding exception,
 * changing return type, etc.) in any other ways than it is requested in the task.
 * 
 * Tasks in this file will give you 4 points.
 */
public class MySigner {
	// FIXMEdone Replace Key type with a proper type from java.security.* package
	public static byte[] dsaSign(byte[] data, PrivateKey signingKey) {
		// FIXMEdone (1p) Implement DSA signing, replace `null` with actual signature value
		return sign("DSA", data, signingKey);
	}

	// FIXMEdone Replace Key type with a proper type from java.security.* package
	public static boolean dsaVerify(byte[] data, byte[] signature, PublicKey verificationKey) {
		// FIXMEdone (1p) Implement DSA verification, replace `false` with actual result (true|false)
		return verify("DSA", data, signature, verificationKey);
	}

	// FIXMEdone Replace Key type with a proper type from java.security.* package
	public static byte[] rsaSign(byte[] data, PrivateKey signingKey) {
		// FIXMEdone (1p) Implement RSA signing, replace `null` with actual signature value
		return sign("RSA", data, signingKey);
	}

	// FIXMEdone Replace Key type with a proper type from java.security.* package
	public static boolean rsaVerify(byte[] data, byte[] signature, PublicKey verificationKey) {
		// FIXMEdone (1p) Implement RSA verification, replace `false` with actual result (true|false)
		return verify("RSA", data, signature, verificationKey);
	}

	// Hints:
	//    You may want to use java.security.Signature class.
	//    You may want to create private methods sign(alg, data, signingKey) and
	//      verify(alg, data, signature, verificationKey) and use them from public methods.
	//      Signing and verification procedures for RSA nd DSA are very similar.

	private static boolean verify(String alg, byte[] data, byte[] signature, PublicKey verificationKey) {
		try {
			Signature sig = Signature.getInstance(alg);
			sig.initVerify(verificationKey);
			sig.update(data);
			return sig.verify(signature);
			
		} catch (SignatureException e) {
			System.out.println("Signature not initialized properly. May not occur.");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algorithm " + alg + " not available. May not occur.");
		} catch (InvalidKeyException e) {
			System.out.println("Invalid key. May not occur.");
		}
		return false;
	}
	
	private static byte[] sign(String alg, byte[] data, PrivateKey signingKey) {
		try {
			Signature sig = Signature.getInstance(alg);
			sig.initSign(signingKey);
			sig.update(data);
			return sig.sign();
			
		} catch (SignatureException e) {
			System.out.println("Signature not initialized properly. May not occur.");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Algorithm " + alg + " not available. May not occur.");
		} catch (InvalidKeyException e) {
			System.out.println("Invalid key. May not occur.");
		}
		return null;
	}
}
