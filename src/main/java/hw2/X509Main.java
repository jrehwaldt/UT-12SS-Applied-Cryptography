package hw2;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/*
 * Here is homework 2.
 * 
 * For that, you will need 4 certificate files.
 * 
 * `cert.pem` is a client certificate -- you can get one from any website that is using SSL.
 * Make sure this certificate has CRL and OCSP extensions. Refer to Labs 6 and 7 for details.
 * 
 * Alternatively, you can get test certificates from here: https://test-sspev.verisign.com/
 * 
 * `root.pem` is CA certificate, self-signed. Depending on what `cert.pem` you've got before,
 * you will need different root certificates. Some oot certificates can be downloaded from
 * http://www.verisign.com/support/roots.html -- or maybe you will need to get these from other CA.
 * 
 * `intermediate1.pem` and `intermediate2.pem` are intermediate certificates issued by the same CA.
 * `intermediate.pem` is signed by `root.pem` and `intermediate2.pem` is signed by
 * `intermediate1.pem`. `cert.pem` is signed by `intermediate2.pem`. Verisign intermediate
 * certificates for extended validation can be found here:
 * http://www.verisign.com/support/verisign-intermediate-ca/extended-validation/index.html
 * For other CAs, just google for exact certificate subject DN -- and you will definitely find
 * where to get these from.
 * 
 * You will have to implement multiple methods in `X509Util` class.
 * 
 * You are allowed to use any BouncyCastle libraries of versions 1.47 (recommended) or 1.46.
 * if you are using 1.46, please add a note to README.txt file included with your solution.
 * 
 * This task will give you 30 points.
 * 
 * When submitting the task, please provide the following files:
 *    - X509Main.java
 *    - X509Util.java
 *    - Util.java (you don't need to change anything there)
 *    - cert.pem
 *    - intermediate1.pem
 *    - intermediate2.pem
 *    - root.pem
 *    - README.txt (optional)
 * 
 * Please use ZIP or tar.gz archives, if needed. Avoid RARs if possible. 
 */
public class X509Main {
	// You should provide these files
	private static final String CERT_FILE = "cert.pem";
	private static final String INTERMEDIATE_CERT_FILE_1 = "intermediate1.pem";
	private static final String INTERMEDIATE_CERT_FILE_2 = "intermediate2.pem";
	private static final String TRUSTED_CERT_FILE = "root.pem";

	// These files are generated automatically. You do not need to provide those.
	private static final String MY_DER_CERT_FILE = "mycert.der";
	private static final String MY_PEM_CERT_FILE = "mycert.pem";
	private static final String MY_CRL_FILE = "my.crl";

	private static int score = 0;

	public static void main(String[] args) throws Exception {
		// Add security providers here, if needed.

		//
		// Modify nothing below.
		//

		testCertificateBasics();
		testCrlBasics();
		testOcspBasics();
		testVerification();
		testChainVerification();

		System.out.println("-----\nFinal score: " + score + "/30");
	}

	/**
	 * Test reading and writing certificates.
	 */
	private static void testCertificateBasics() throws Exception {
		// Reading certificate from file
		X509Certificate certificate = X509Util.readCertificate(new FileInputStream(CERT_FILE));
		System.out.println("Serial: " + certificate.getSerialNumber());
		System.out.println("Issuer: " + certificate.getIssuerDN() + " (1p)");
		score += 1;

		try {
			// Writing DER-encoded certificate to file
			X509Util.writeDer(new FileOutputStream(MY_DER_CERT_FILE), certificate);
			certificate = X509Util.readCertificate(new FileInputStream(MY_DER_CERT_FILE));
			System.out.println("DER writing check passed (1p)");
			score += 1;
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("DER writing check FAILED");			
		}

		try {
			// Writing PEM-encoded certificate to file
			X509Util.writePem(new FileOutputStream(MY_PEM_CERT_FILE), certificate);

			// Comparing created PEM file with original certificate file
			byte[] certificateBytes = Util.readFile(CERT_FILE);
			byte[] newCertificateBytes = Util.readFile(MY_PEM_CERT_FILE);
			if (!Arrays.equals(certificateBytes, newCertificateBytes)) {
				throw new IllegalStateException("PEM files differ");
			}
			System.out.println("PEM writing check passed (3p)");
			score += 3;
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("PEM writing check FAILED");
			// Reached this but files seem the same?
			// Try `diff <file> <another-file>` to make sure they are different.
			// If that is the case, pay attention to line separators.
			// Hint: you can change those in Java.
			//
			// Special note to Windows users: make sure your code will pass the test on Linux too!
		}
	}

	private static void testCrlBasics() throws Exception {
		X509Certificate certificate = X509Util.readCertificate(new FileInputStream(CERT_FILE));

		// Downloads CRL for this certificate
		String crlUrl = X509Util.getCrlUrl(certificate);
		Util.download(new URL(crlUrl), MY_CRL_FILE);
		System.out.println("Downloaded CRL from: " + crlUrl + " (5p)");
		score += 5;
		// If you have troubles with this task, comment this section out and download CRL file
		// manually. Save it as 'my.crl' next to other files this program has created.

		X509CRL crl = X509Util.readCrl(new FileInputStream(MY_CRL_FILE));
		System.out.println("Issuer: " + crl.getIssuerDN() + " (1p)");
		score += 1;
	}

	private static void testOcspBasics() throws Exception {
		X509Certificate certificate = X509Util.readCertificate(new FileInputStream(CERT_FILE));

		// Downloads CRL for this certificate
		String ocspUrl = X509Util.getOcspUrl(certificate);
		System.out.println("OCSP URL: " + ocspUrl + " (3p)");
		score += 3;
		// If you have troubles with this task, comment this section out and download CRL file
		// manually. Save it as 'my.crl' next to other files this program has created.
	}

	private static void testVerification() throws Exception {
		X509Certificate certificate = X509Util.readCertificate(new FileInputStream(CERT_FILE));
		X509CRL crl = X509Util.readCrl(new FileInputStream(MY_CRL_FILE));
		X509Certificate issuerCertificate = X509Util.readCertificate(new FileInputStream(INTERMEDIATE_CERT_FILE_2));

		try {
			score += X509Util.verify(certificate, issuerCertificate, crl);
		} catch (CertificateException e) {
			e.printStackTrace();
			System.err.println("Certificate verification check FAILED");
		}
	}

	private static void testChainVerification() throws Exception {
		X509Certificate certificate = X509Util.readCertificate(new FileInputStream(CERT_FILE));
		X509Certificate trustedCertificate = X509Util.readCertificate(new FileInputStream(TRUSTED_CERT_FILE));
		X509Certificate[] intermediateCertificates = {
				X509Util.readCertificate(new FileInputStream(INTERMEDIATE_CERT_FILE_1)),
				X509Util.readCertificate(new FileInputStream(INTERMEDIATE_CERT_FILE_2))
		};
		
		// Note that order of intermediate certificates may change.
		// Verification result should be the same.

		try {
			score += X509Util.verifyChain(certificate, trustedCertificate, intermediateCertificates);
		} catch (CertificateException e) {
			e.printStackTrace();
			System.err.println("Certificate chain verification check FAILED");
		}
	}
}
