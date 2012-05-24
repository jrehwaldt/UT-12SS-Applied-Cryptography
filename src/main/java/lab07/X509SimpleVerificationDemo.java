package lab07;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/*
 * Demonstrates how to perform a simple verification of X.509 certificate.
 * 
 * Simplifying it, X.509 certificate is a container for public key and signature.
 * Signature was created using certificate issuer's private key, whose corresponding
 * public key can be found in the issuer's own certificate. So, to verify the signature
 * of your certificate, you will need to get the issuer's certificate and extract
 * public key from there.
 * 
 * Your certificate's IssuerDN field has the needed information where to get issuer's
 * certificate from (or at least how to identify that).
 * 
 * Note that these steps are only part of full certificate verification process,
 * this code is here for demo purposes only and is not ready for production.
 * 
 * To do a complete verification, you should also verify
 *   - certificate validity dates (demo done in class),
 *   - certificate revocation status (using OCSP or CRL -- see CrlDemo.java),
 *   - issuer's certificate (signature, validity, revocation status) and also
 *     every certificate in trust chain until you get to the trusted one.
 */
public class X509SimpleVerificationDemo {
	public static void main(String args[]) throws Exception {
		FileInputStream in = null;
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

		// First argument should be the path to the certificate file being verified.
		in = new FileInputStream(args[0]);
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);

		// Second parameter should be the path to issuer certificate file.
		in = new FileInputStream(args[1]);
		X509Certificate issuerCertificate =
				(X509Certificate) certificateFactory.generateCertificate(in);

		// Certificate issuer's name and issuer certificate subject name should match.
		// If they don't, you've probably got the wrong issuer certificate.
		System.out.println(certificate.getIssuerDN());
		System.out.println(issuerCertificate.getSigAlgName());

		// Actual verification -- this method has no return value, however,
		// it'll throw an exception if something goes wrong with signature verification.
		certificate.verify(issuerCertificate.getPublicKey());
		System.out.println("Certificate signature verified successfully");
	}
}
