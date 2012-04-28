package hw2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;

/*
 * Fix all the TODO's. Follow the Javadoc.
 * 
 * You are *not* allowed to change method signatures.
 */
public final  class X509Util {
	/**
	 * Extracts first CRL distribution URL from this X.509 certificate.
	 */
	public static String getCrlUrl(X509Certificate certificate)
			throws IOException {
		// TODO: implement.
		//
		// Your first step is to extract CRL extension value from this certificate.
		//
		// As per http://tools.ietf.org/html/rfc5280#section-4.2.1.13, CRLDistributionPoints
		// extension is defined as follows:
		//
		// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
		//
		// DistributionPoint ::= SEQUENCE {
		//    distributionPoint  [0]  DistributionPointName OPTIONAL
		//     -- some fields skipped
		// }
		// 
		// DistributionPointName ::= CHOICE {
		//     fullName  [0]  GeneralNames
		//     -- some fields skipped
		// }
		// 
		// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
		// 
		// GeneralName ::= CHOICE {
		//     -- some fields skipped
		//     uniformResourceIdentifier [6]  IA5String -- also known as URI
		//     -- some fields skipped
		// }
		// 
		// encapsulated in OCTET STRING. So if reading the extension value, you should get something
		// like this:
		// 
		// OCTET STRING, encapsulates { -- extension value
		//     SEQUENCE { -- cRLDistributionPoints
		//         SEQUENCE { -- distributionPoint
		//             [0] { -- fullName
		//                 [0] { -- uniformResourceIdentifier
		//                     [6] 'some-url-here' -- CRL URL you need
		//                 }
		//             }
		//         }
		//     }
		// }
		// 
		// Check out the helper method, toAsn1Object(byte[]) -- you can use it to convert
		// byte array to ASN.1 object.
		//
		// Some examples to help you get started:
		//   ASN1Sequence foo = (ASN1Sequence) bar // converts ASN1Encodable bar to ASN1Sequence
		//   ASN1Primitive fubar = baz.getObject() // extracts object from ASN1TaggedObject baz
		//
		// Hint: you can find CRL extension OID if you print the certificate contents.
		
		return null;
	}

	/**
	 * Extracts OCSP service URL from this X.509 certificate.
	 */
	public static String getOcspUrl(X509Certificate certificate)
			throws IOException {
		// TODO: implement.
		//
		// Once you have implemented getCrlUrl(X509Certificate) method, this one should be easy
		// to complete. The logic behind extracting values is the same, only the structures are
		// slightly different.
		//
		// Check out http://tools.ietf.org/html/rfc5280#section-4.2.2.1 for details.
		
		return null;
	}

	/**
	 * Reads X.509 certificate from this input stream.
	 */
	public static X509Certificate readCertificate(InputStream in)
			throws CertificateException, IOException {
		// TODO: implement.
		//
		// Challenge: make it one-liner.
		
		return null;
	}

	/**
	 * Reads X.509 CRL object from this input stream.
	 */
	public static X509CRL readCrl(InputStream in)
			throws CertificateException, CRLException, IOException {
		// TODO: implement.
		//
		// Challenge: make it one-liner.
		
		return null;
	}

	/**
	 * Performs full certificate verification.
	 * 
	 * Properties checked:
	 *   - Validity dates
	 *   - Issuer DN
	 *   - Public key signature
	 *   - Certificate revocation status
	 * 
	 * If OCSP service is not reachable (no connection), certificate status is checked using CRL.
	 * 
	 * If CRL check is not possible, certificate considered not valid.
	 * 
	 * @throws CertificateException in case of any verification problems.
	 */
	public static int verify(
			X509Certificate certificate, X509Certificate issuerCertificate, X509CRL crl)
					throws CertificateException {
		// TODO: implement.
		//
		// If any of verification steps fails, a CertificateException should be thrown containing
		// a short but precise description of the problem.
		//
		// This method returns the number of points you will get.
		// Currently score is set to maximum, I assume you'll do the task properly (:
		//
		// I'll fix these numbers while reviewing your code.
		// Should it contain any problems, the score will get lower ):
		//
		// As for now, you may use any numbers you are happy with, they shouldn't affect the
		// actual certificate verification process.
		int score = 0;

		// TODO: verify certificate validity issuer
		score += 1; // I may change these while reviewing your code.

		// TODO: verify certificate validity dates
		score += 1;

		// TODO: verify public key signature
		score += 1;

		// TODO: check certificate status via OCSP. report status code in case of failure.
		//
		// It is okay to use some deprecated BouncyCastle classes here, if needed. These will make
		// your life much easier.
		//
		// Check lab 7 code for examples.
		score += 3;

		// TODO: verify CRL signature and check if certificate was revoked
		score += 3;

		return score;
	}
	
	/**
	 * Verifies certificate chain.
	 */
	public static int verifyChain(
			X509Certificate certificate, X509Certificate trustedCertificate,
			X509Certificate[] intermediateCertificates) 
	throws Exception {
		// TODO: implement.
		//
		// These classes may be helpful:
		//    - java.security.cert.TrustAnchor
		//    - java.security.cert.CertStore
		//    - java.security.cert.PKIXBuilderParameters
		//    - java.security.cert.CertPathBuilder
		//    - java.security.cert.CertPathValidator
		//
		// You may skip CRL checks here -- see PKIXBuilderParameters.setRevocationEnabled(boolean)
		int score = 0;
		
		// TODO: verify trusted certificate public key signature
		score += 1;
		
		// TODO: create a set of trust anchors.
		
		// TODO: create a list of all certificates being verified.
		
		// TODO: create a certificate store.

		// TODO: Build the certificate chain.
		score += 2;
		
		// TODO: Verify the certificate chain.
		score += 4;
		
		return score;
	}

	/**
	 * Encoded this X.509 certificate using DER and writes the result to this output stream.
	 */
	public static void writeDer(OutputStream out, X509Certificate certificate)
			throws CertificateEncodingException, IOException {
		// TODO: implement
	}

	/**
	 * Encoded this X.509 certificate using PEM rules and writes the result to this output stream.
	 */
	public static void writePem(OutputStream out, X509Certificate certificate)
			throws CertificateEncodingException, IOException {
		// TODO: implement.
		//
		// Hint: `org.bouncycastle.util.io.pem.*` package may be useful.
		//
		// Note that you will get penalty (2p) for using `sun.misc.*` classes directly!
	}



	private static ASN1Encodable toAsn1Object(byte[] encoded)
			throws IOException {
		return new ASN1InputStream(encoded).readObject(); 
	}
}
