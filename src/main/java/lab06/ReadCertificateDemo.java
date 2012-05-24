package lab06;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/*
 * Demonstrates how to read X.509 certificate from file and print the certificate contents.
 */
public class ReadCertificateDemo {
	public static void main(String[] args) throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

		FileInputStream in = new FileInputStream(args[0]);

		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);
		System.out.println(certificate);
	}
}
