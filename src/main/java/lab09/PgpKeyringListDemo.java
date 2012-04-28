package lab09;

import java.io.FileInputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

/*
 * Demonstrates how to access PGP public keyring.
 * 
 * To run this program correctly, its first parameter should be the path to public keyring.
 * 
 * If running from command line, something like this should work:
 *     java -cp .:bcpg.jar:bcprov.jar lab09.PgpDemo ~/.gnupg/pubring.gpg
 * 
 *  If running from Eclipse, make sure to set up
 *      Run > Run Configurations... > Arguments > Program arguments
 *  to '/home/user/.gnupg/pubring.gpg' or whatever you public keyring file path is.
 *  Note that you may need to provide the full path.
 */
public class PgpKeyringListDemo {
	public static void main(String args[]) throws Exception {
		// First, keyring collection file is read
		FileInputStream in = new FileInputStream(args[0]);
		PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(in);

		// Then, keyrings are extracted. In terms of BouncyCastle, keyring is a set of
		// one master key and several (may be 0) subkeys, each signed with this master key.
		Iterator<?> keyRingIterator = keyRingCollection.getKeyRings();
		while (keyRingIterator.hasNext()) {
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIterator.next();

			// Finally, keys are extracted from this keyring.
			Iterator<?> keyIterator = keyRing.getPublicKeys();
			while (keyIterator.hasNext()) {
				// Print key params
				PGPPublicKey pgpPublicKey = (PGPPublicKey) keyIterator.next();
				System.out.println("Key: " + (pgpPublicKey.isMasterKey() ? "pub" : "sub"));
				System.out.println("Length: " + pgpPublicKey.getBitStrength());
				System.out.println("ID: " + Long.toHexString(pgpPublicKey.getKeyID()).toUpperCase());
				System.out.println("Valid from: " + pgpPublicKey.getCreationTime());

				// Print key fingerprint
				System.out.println("Key fingerprint: " + pgpPublicKey.getFingerprint());
//				System.out.println("Key fingerprint: " + Util.toHexString(pgpPublicKey.getFingerprint()));

				// Print user IDs
				Iterator<?> userIdIterator = pgpPublicKey.getUserIDs();
				while (userIdIterator.hasNext()) {
					String userId = (String) userIdIterator.next();
					System.out.println("User ID: " + userId);
				}

				System.out.println();
			}
		}
	}
}
