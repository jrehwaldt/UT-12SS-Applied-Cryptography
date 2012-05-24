package lab19;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import common.EstEidHandler;
import common.SmartCardUtil;

public class EstEidCryptoDemo {
	public static void main(String[] args) throws Exception {
		/*
		 * Before you start:
		 * 
		 * Create a file .esteid.conf with the following content:
		 * 
		 * pin1 = 0000
		 * pin2 = 00000
		 * puk = 00000000
		 * 
		 * Replace 000-s with your code values. This file will be used to read
		 * security codes from. Hard-coding those is definitely a bad idea.
		 * 
		 * Put the file to your home folder, on UNIX/Linux:
		 *   /home/<username>/.esteid.conf
		 * on OS X:
		 *   /Users/<username>/.esteid.conf
		 * on Windows 7:
		 *   C:\Users\<username>\.esteid.conf
		 * others -- see
		 * http://en.wikipedia.org/wiki/Home_directory#Default_Home_Directory_per_Operating_System
		 * 
		 * * * *
		 * 
		 * Check EstEidHandler's javadoc at http://bit.ly/appcrypto2012lab19doc
		 * 
		 * (note: updated 2012-05-11)
		 * 
		 * * * *
		 * 
		 * Check EstEidHandler's code at
		 * https://bitbucket.org/hudolejev/applied-cryptography-2012-course/src/tip/common/EstEidHandler.java
		 * 
		 * (note: updated 2012-05-11)
		 * 
		 * * * *
		 * 
		 * Continue with tasks...
		 */

		byte[] data = "All your base are belong to us.".getBytes();

		// Connect the card, initialize the common.EstEidHandler
		EstEidHandler eid = new EstEidHandler(SmartCardUtil.connectCard().getBasicChannel());
		eid.loadProperties();

		// Print personal code and document validity period (start date, end date).
		System.out.println("Personal code: " + eid.getPersonalCode());
		System.out.println("Document valid from: " + eid.getDocumentValidFrom());
		System.out.println("Document valid until: " + eid.getDocumentValidUntil());

		// Get certificates from the card.
		X509Certificate authenticationCertificate = eid.getAuthenticationCertificate();
		X509Certificate signingCertificate = eid.getSigningCertificate();

		// Q: What certificates could you find?
		// Q: What are certificates' validity periods?
		// Q: How are certificates different?

		// Compare card's validity period with certificate's one.
		// Q: Do they match?
		// Hint: check `readPersonalDataRecord(int)` code comments.

		// Create signature using ID-card built-in functionality.
		// EstEID versions prior to 3.0 (before 2011) only supported signing
		// algorithm SHA1withRSA and 1024-bit keys.
		// v3.0 also supports SHA-224, SHA256 and 2048-bit keys.
		//
		// There are two ways to create signatures. One option is to feed the
		// raw data, so that digest is computed on the card and then signed.
		// This method is easy, but may be slow as card's computational resources
		// are very limited.
		byte[] signatureBytes = eid.signData(data);
		verifySignature(data, signatureBytes, signingCertificate);
		System.out.println("PIN2 attempts remaining: " + eid.getPinAttemptsRemaining(2));

		// Another option is to pre-compute the digest, and feed computed
		// digest bytes to card. This method is faster but requires some
		// ASN.1 magic to meet card's protocol requirements.
		//
		// See also:
		// http://dl.dropbox.com/u/1536081/EstEidHandler-javadoc/common/EstEidHandler.html#signDigest%28byte[]%29

		// TODO: implement

		// Hint: you may want to use org.bouncycastle.asn1.tsp.MessageImprint class
		// Hint: SHA-1 OID is 1.3.14.3.2.26 



		// Encrypt some data using  authentication certificate
		// from the card. Decrypt it using Smart Card built-in functionality.
		//
		// Note: for demo purposes, EstEidHandler only supports ciphertexts
		// up to 128 bytes. Choose your raw data respectively.
		//
		// See also:
		// http://dl.dropbox.com/u/1536081/EstEidHandler-javadoc/common/EstEidHandler.html#decryptData%28byte[]%29

		// TODO: implement

		// Hint: check out homework 1 -- can re-use some code from there



		// All done.
	}

	public static void verifySignature(
			byte[] data, byte[] signatureBytes, X509Certificate certificate)
					throws GeneralSecurityException {
		boolean result = false; // TODO: implement

		System.out.println("Signature " + (result ? "" : "NOT") + " valid");
	}
}
