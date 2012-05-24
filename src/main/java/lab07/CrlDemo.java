package lab07;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/*
 * Demonstrates how to use CRLs to check X.509 certificate revocation status.
 * 
 * CRL file should be downloaded separately. CRL file URL can usually be found in
 * certificate extension called 'CRLDistributionPoints' (OID: 2.5.29.31).
 */
public class CrlDemo {
	public static void main(String[] args) throws Exception {
		FileInputStream in = null;
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

		// First argument should be the path to the certificate file being verified.
		in = new FileInputStream(args[0]);
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);

		// Second argument should be the path to issuer certificate file.
		in = new FileInputStream(args[1]);
		X509Certificate issuerCertificate =
				(X509Certificate) certificateFactory.generateCertificate(in);

		// Third argument should be the path to CRL file (downloaded separately).
		// CRL file URL is available from CRL extension of the certificate being verified.
		in = new FileInputStream(args[2]);
		X509CRL crl = (X509CRL) certificateFactory.generateCRL(in);

		// CRL signature should be verified to ensure CRL's consistency and authenticity.
		crl.verify(issuerCertificate.getPublicKey());

		// Finally, search a certificate being verified in revoked certificates list.
		if (crl.getRevokedCertificate(certificate) == null) {
			System.out.println("CRL check passed");
		} else {
			System.out.println("CRL: Certificate was revoked!");
		}
	}
}
