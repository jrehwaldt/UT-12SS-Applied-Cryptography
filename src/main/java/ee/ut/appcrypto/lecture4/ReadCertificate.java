package ee.ut.appcrypto.lecture4;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ReadCertificate {
	
	/**
	 * Hints: 
	 *  Check out javadoc for java.security.cert.X509Certificate. 
	 * 
	 * Q: 
	 *  What encoding is certificate saved in? 
	 *  How long is the certificate valid? Why so? 
	 *  What is IssuerDN and what is SubjectDN? What format is used? 
	 *  What is the signature algorithm? What exactly is signed? 
	 */
	public static void main(String... args) throws CertificateException, IOException {
		
		FileInputStream fis = new FileInputStream("src/main/resources/sso.ut.ee.cer");
		
		CertificateFactory factory = CertificateFactory.getInstance("X509");
		java.security.cert.X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
		fis.close();
		
		System.out.println(cert);
		
		// Encoding:           Base 64 or DER-binäry
		// Distinguished Name: LDAP (Active Directory) format, RFC 4514
		// What is signed?:    the public key
		
//		System.out.println("Signing Algorithm: " + cert.getSigAlgName() + " [" + cert.getSigAlgOID() + "]");
//		System.out.println("Basic Constraints: " + cert.getBasicConstraints());
//		System.out.println("Due date:\t" + cert.getNotAfter());
//		System.out.println("Issuer DN:\t" + cert.getIssuerDN());
//		System.out.println("Subject DN:\t" + cert.getSubjectDN());
//		System.out.println("Type:\t\t" + cert.getType());
//		System.out.println("Version:\t\t" + cert.getVersion());
	}
}
