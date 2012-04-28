package hw2;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

/*
 * Another task of Homework 2.
 * 
 * This task is all about OpenPGP standard, see also: http://tools.ietf.org/html/rfc4880
 * 
 * You will have to implement multiple methods in `OpenpgpUtil` class.
 * 
 * For testing this code, you will need an OpenPGP keystore created containing
 * at least one key. Make sure to experiment with different key properties.
 * 
 * Refer to Lab 8 for details on how to generate PGP keys:
 * http://courses.cs.ut.ee/2012/appcrypto/08/01
 * 
 * If using GnuPG, your keystore will most likely be located in `~/.gnupg/pubring.gpg`.
 * Copy (or link) it to the same directory you will be running your code from
 * (example for Eclipse: /home/user/workspace/MyProject/pubring.gpg).
 * Make sure this directory contains the file called 'pubring.gpg', or change the
 * file name constants accordingly (see below).
 * 
 * You will also need one exported public key in a separate file, 'pubkey.gpg'.
 * Put it into the same directory you will be running your code from.
 * 
 * Refer to Lab 9 for details on how to export PGP keys:
 * http://courses.cs.ut.ee/2012/appcrypto/09/02
 * 
 * It is up to you either using you own key here or someone's else.
 * 
 * Notes:
 *  In terms of OpenPGP, public keys are organized into keyrings, each containing
 *  one master key and multiple (may be 0) subkeys. Master key is used for signing,
 *  and subkeys are usually used for encryption. Master key also identifies the owner
 *  and gets signed by another people (not covered in these tasks).
 *  Keyrings are organized into collections, each containing multiple keyrings.
 *  'pubring.gpg' file contains OpenGPG keyring collection.
 * 
 * You are allowed to use any BouncyCastle libraries of versions 1.47 (recommended) or 1.46.
 * If you are using 1.46, please add a note to README.txt file included with your solution.
 * 
 * This task will give you 10 points.
 * 
 * When submitting the task, please provide the following files:
 *    - OpenpgpMain.java
 *    - OpenpgpUtil.java
 *    - Util.java (you don't need to change anything there)
 *    - README.txt (optional)
 * 
 * Please use ZIP or tar.gz archives, if needed. Avoid RARs if possible.
 */
public class OpenpgpMain {
	// If changing these, make sure to provide your own files used for testing
	private static final String KEYSTORE_FILE = "pubring.gpg";
	private static final String NEW_KEYSTORE_FILE = "new-pubring.gpg";
	private static final String PUBLIC_KEY_FILE = "pubkey.gpg";

	private static int score = 0;

	public static void main(String[] args) {
		PGPPublicKeyRingCollection keyRingCollection = null;
		PGPPublicKeyRing keyRing = null;

		// Read OpenPGP public keyring from file and list its contents.
		try {
			keyRing = OpenpgpUtil.readPublicKeyRing(PUBLIC_KEY_FILE);
			score += 1;
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Keyring reading check FAILED");
		}

		try {
			OpenpgpUtil.listPublicKeyRing(keyRing);
			score += 6;
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Keyring listing check FAILED");
		}

		System.out.println("--------");

		// Read OpenPGP public keyring collection from file and list its contents.
		try {
			keyRingCollection = OpenpgpUtil.readPublicKeyRingCollection(KEYSTORE_FILE);
			score += 1;
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Collection reading check FAILED");
		}

		try {
			OpenpgpUtil.listPublicKeyRingCollection(keyRingCollection);
			score += 1;
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Collection listing check FAILED");
		}

		// Add this keyring to this keyring collection
		keyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(keyRingCollection, keyRing);

		// Write new keyring collection to file.
		try {
			OpenpgpUtil.writePublicKeyRingCollection(keyRingCollection, NEW_KEYSTORE_FILE);
			score += 1;
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Collection listing check FAILED");
		}

		System.out.println("-----\nFinal score: " + score + "/10");
	}
}
