package hw3;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import common.EstEidHandler;
import common.SmartCardUtil;

/**
 * This class is used by BouncyCastle SignerIngoGeneratorBuilders to acquire signatures
 * for a raw data using Estonian ID card as signature provider (signer).
 * 
 * First the data is fed to the output stream handled by this class
 * (see {@link #getOutputStream()}). After all the data is written, {@link #getSignature()}
 * method is called to compute the signature for the data.
 * 
 * (all tasks: 6p)
 */
public class MyEstEidSigner implements ContentSigner {
	private ByteArrayOutputStream out = null;

	/*
	 * Some methods are implemented so you could get a better overview of what is
	 * happening here. Your task is to implement remaining methods.
	 * 
	 * Check comments inside methods for details.
	 */

	public MyEstEidSigner() {
		this.out = new ByteArrayOutputStream();
	}

	public AlgorithmIdentifier getAlgorithmIdentifier() {
		return new AlgorithmIdentifier(OIWObjectIdentifiers.sha1WithRSA);
	}

	/**
	 * Returns certificate that can be used for this signature verification.
	 * 
	 * (1p)
	 */
	public X509Certificate getCertificate() {
		// TODOdone: implement
		//
		// This method should throw IllegalStateException if anything goes wrong with the card.
		// Make sure to set original exception as new exception cause.
		try {
			@SuppressWarnings("restriction")
			EstEidHandler eid = new EstEidHandler(SmartCardUtil.connectCard().getBasicChannel());
			eid.loadProperties();
			
			// Get certificates from the card.
			X509Certificate signingCertificate = eid.getSigningCertificate();
			return signingCertificate; // FIXMEdone
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public OutputStream getOutputStream() {
		return out;
	}

	/**
	 * Computes signature over data previously written to this output stream.
	 * 
	 * Signature is computed using Estonian ID card functionality.
	 * 
	 * To get the certificate for signature verification, use {@link #getCertificate()} method.
	 * 
	 * (5p)
	 */
	public byte[] getSignature() {
		/*
		 * Before you start implementing this method, make sure you understand how signing
		 * process works on Estonian ID cards. Refer to lab 19 task for examples and docs:
		 * https://bitbucket.org/hudolejev/applied-cryptography-2012-course/src/tip/lab19/EstEidCryptoDemo.java
		 */
		
		// TODOdone: implement
		//   - Compute message imprint from the data written 'out' stream
		//   - Sign message imprint using EstEID card
		//
		// Make sure to choose the algorithms supported by older cards as well.
		//
		// Note that you have to sign the digest, not the raw data.
		//
		// This method should throw IllegalStateException if anything goes wrong with the card
		// or message imprint structure. Make sure to set original exception as new exception cause.
		//
		// Hints:
		//  - Check out http://dl.dropbox.com/u/1536081/EstEidHandler-javadoc/common/EstEidHandler.html#signDigest%28byte[]%29
		//  - Check out lab 19 code for some examples
		//  - Check out org.bouncycastle.asn1.tsp.MessageImprint
		//  - Make sure to have PIN2 set in .esteid.conf -- also check out EstEidHandler class docs
		//  - Do *not* keep your PINs hard-coded (penalty: 10 points); read PINs from config files
		
		try {
			@SuppressWarnings("restriction")
			EstEidHandler eid = new EstEidHandler(SmartCardUtil.connectCard().getBasicChannel());
			eid.loadProperties();
			
			byte[] unsigned = out.toByteArray();
			
			MessageImprint imprint = new MessageImprint(
					getAlgorithmIdentifier(),
					eid.signData(unsigned));
			
			return imprint.getEncoded(); // FIXMEdone
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}
}
