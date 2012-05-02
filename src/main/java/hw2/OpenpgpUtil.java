package hw2;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Calendar;
import java.util.Iterator;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;

/*
 * Hints:
 *  - You can use `gpg` command-line tool to check the contents of keyrings and
 *    collections and compare it to output you are getting from your methods.
 */
public class OpenpgpUtil {
	/*
	 * Read this task carefully. There are lots of tricky details, and only
	 * meeting *all* of the requirements will give you the maximum of 6 points.
	 */
	/**
	 * Prints this OpenPGP keyring contents to stdout (6 p).
	 * 
	 * Output format MUST be the following:
	 * 
	 * Key: <key-type> v<key-version> <key-length>-bit <key-algorithm>
	 * ID: <key-id>
	 * Valid from: <key-valid-from-time> (<key-valid-from-unixtime>)
	 * Valid until: <key-valid-until-time> (<key-valid-until-unixtime>)
	 * Key fingerprint: <key-fingerprint> (<key-fingerprint-algorithm>)
	 * User ID: <key-user-id>
	 * Signed by: <signing-key-id>
	 * <empty-line>
	 * 
	 * Whereas
	 *  - <key-type> -- 'pub' for master key or 'sub' for subkey
	 *  - <key-version> -- key version (a number)
	 *  - <key-length> -- key length, in bits (a number)
	 *  - <key-algorithm> -- key algorithm name (RSA, DSA, Elgamal, etc.)
	 *  - <key-id> -- key identifier, last 8 bytes of key fingerpint, upper case
	 *  - <key-valid-from-time> -- free-text date and time (see example below)
	 *  - <key-valid-from-unixtime> -- UNIX time, in seconds
	 *  - <key-valid-until-time> -- free-text date and time ('forever' if key has no expiration date)
	 *  - <key-valid-from-unixtime> -- UNIX time, in seconds (-1 if key has no expiration date)
	 *  - <key-fingerprint> -- digest of key parameters (as defined in RFC 4880), in lower case
	 *  - <key-user-id> -- key user identifier, including name, alias and email (see example below)
	 *  - <signing-key-id> -- identifier of the key that was used to sign this key
	 *  
	 * Example output:
	 *   Key: pub v3 1024-bit DSA
	 *   ID: DE01AD23BE45EF67
	 *   Valid from: Mon Mar 5 06:07:08 EET 2012 (1330920428)
	 *   Valid until: forever (-1)
	 *   Key fingerprint: 0123456789abcdef0123456789abcdef (MD5)
	 *   User ID: John Doe (fubar) <john.doe@gmail.com>
	 *   Signed by: 76DE54AD32BE10EF
	 *   
	 * Notes:
	 *  - There may be multiple 'User ID:' lines
	 *  - There may be multiple 'Signed by:' lines
	 *  - Some keys may be self-signed ('ID:' and 'Signed by:' values will match)
	 *  - Make sure to leave an empty line after the last line with text
	 * 
	 * See also:
	 *  - Public key algorithms: http://tools.ietf.org/html/rfc4880#section-9.1
	 *  - Public key IDs and fingerprints: http://tools.ietf.org/html/rfc4880#section-12.2
	 */
	@SuppressWarnings("unchecked")
	public static void listPublicKeyRing(PGPPublicKeyRing keyRing) {
		// TODOdone: implement
		// Hint: use String.format() to build strings with multiple variables.
		
		Iterator<?> keyIterator = keyRing.getPublicKeys();
		while (keyIterator.hasNext()) {
			PGPPublicKey pgpPublicKey = (PGPPublicKey) keyIterator.next();
			
			String keyType = pgpPublicKey.isMasterKey() ? "pub" : "sub";
			int keyVersion = pgpPublicKey.getVersion();
			int keyLength = pgpPublicKey.getBitStrength();
			String keyAlgorithm = toAlgorithmString(pgpPublicKey.getAlgorithm());
			
			String validFrom = pgpPublicKey.getCreationTime().toString();
			long validFromUnix = pgpPublicKey.getCreationTime().getTime() / 1000;
			String validUntil = "forever";
			long validUntilUnix = -1;
			
			int validDays = pgpPublicKey.getValidDays();
			if (validDays > 0) {
				Calendar tmp = Calendar.getInstance();
				tmp.setTime(pgpPublicKey.getCreationTime());
				tmp.add(Calendar.DAY_OF_YEAR, validDays);
				
				validUntil = tmp.getTime().toString();
				validUntilUnix = tmp.getTimeInMillis() / 1000;
			}
			
			String fingerprint = new String(Hex.encode(pgpPublicKey.getFingerprint()));
			String fingerprintAlgorithm = "Undefined";
			
			if (keyVersion == 3) {
				fingerprintAlgorithm = "MD5";
			} else if (keyVersion == 4) {
				fingerprintAlgorithm = "SHA-1";
			}
			
			// Print key params
			System.out.println(String.format("Key: %s v%d %d-bit %s", keyType, keyVersion, keyLength, keyAlgorithm));
			System.out.println(String.format("ID: %S", Long.toHexString(pgpPublicKey.getKeyID())));
			System.out.println(String.format("Valid from: %s (%d)", validFrom, validFromUnix));
			System.out.println(String.format("Valid until: %s (%d)", validUntil, validUntilUnix));
			
			// Print key fingerprint
			System.out.println(String.format("Key fingerprint: %s (%s)", fingerprint, fingerprintAlgorithm));
			
			// Print user user ids
			Iterator<String> userIds = pgpPublicKey.getUserIDs();
			while (userIds.hasNext()) {
				String userId = (String) userIds.next();
				System.out.println(String.format("User ID: %s", userId));
			}
			
			// print signatures
			Iterator<PGPSignature> signatures = pgpPublicKey.getSignatures();
			while (signatures.hasNext()) {
				PGPSignature signature = (PGPSignature) signatures.next();
				String sig = Long.toHexString(signature.getKeyID());
				System.out.println(String.format("Signed by: %S", sig));
			}
			
			System.out.println();
		}
	}

	/**
	 * Prints this OpenPGP keyring collection contents to stdout (1 p).
	 */
	public static void listPublicKeyRingCollection(PGPPublicKeyRingCollection keyRingCollection) {
		// TODOdone: implement
		// Hint: use listPublicKeyRing(PGPPublicKeyRing) method.
		
		@SuppressWarnings("unchecked")
		Iterator<PGPPublicKeyRing> rings = keyRingCollection.getKeyRings();
		while (rings.hasNext()) {
			listPublicKeyRing(rings.next());
		}
	}

	/**
	 * Reads OpenPGP public keyring from this file (1p).
	 */
	public static PGPPublicKeyRing readPublicKeyRing(String filePath)
			throws IOException {
		// TODOdone: implement
		
		FileInputStream in = new FileInputStream(filePath);
		PGPPublicKeyRing ring = new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
		return ring;
	}

	/**
	 * Reads OpenPGP public keyring collection from this file (1p).
	 */
	public static PGPPublicKeyRingCollection readPublicKeyRingCollection(String filePath)
			throws IOException, PGPException {
		// TODOdone: implement
		
		FileInputStream in = new FileInputStream(filePath);
		PGPPublicKeyRingCollection coll = new PGPPublicKeyRingCollection(in);
		return coll;
	}

	/**
	 * Writes this OpenPGP public keyring collection to this file (1p).
	 */
	public static void writePublicKeyRingCollection(
			PGPPublicKeyRingCollection keyRingCollection, String filePath)
					throws IOException {
		// TODOdone: implement
		
		FileOutputStream fos = new FileOutputStream(filePath);
		fos.write(keyRingCollection.getEncoded());
		fos.flush();
		fos.close();
	}
	
	private static String toAlgorithmString(int code) {
		switch (code) {
		case PublicKeyAlgorithmTags.RSA_GENERAL:
		case PublicKeyAlgorithmTags.RSA_ENCRYPT:
		case PublicKeyAlgorithmTags.RSA_SIGN:
			return "RSA";
		case PublicKeyAlgorithmTags.DSA:
			return "DSA";
		case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
		case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
			return "Elgamal";
		case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
			return "Diffie Hellman";
		case PublicKeyAlgorithmTags.EC:
			return "EC";
		case PublicKeyAlgorithmTags.ECDSA:
			return "ECDSA";
		default:
			return "Unknown";
		}
	}
}