package hw3;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Imports SK certificates to use by MyServer.
 * 
 * This class is run once to download and store certificates to local keystore.
 * Later, MyServer will read SK certificates from local keystore.
 * 
 * Do *not* run this code on every server start and make sure not to
 * abuse SK servers with lots of unnecessary requests.
 * 
 * (all tasks: 4p)
 */
public class MyCertificateImporter {
	/**
	 * (3p)
	 */
	public static void main(String[] args) throws Exception {
		MyConf.load(); // Loads configuration properties
		
		// Required certificates -- update this list if SK issues new certificates.
		// These URLs should be set in configuration file -- see MyConf class.
		// See also: // http://sk.ee/en/repository/certs/
		String[] urls = {
				System.getProperty("my.sk.certificate.estEid1.url"),
				System.getProperty("my.sk.certificate.estEid2.url"),
				System.getProperty("my.sk.certificate.root1.url"),
				System.getProperty("my.sk.certificate.root2.url"),
		};

		// TODOdone: Download all certificates listed in urls[], add these to a new
		// keystore save it to disk and (3p)
		//
		// Keystore path should be configured in 'my.sk.keyStore' property.
		// Keystore password should be set in 'my.sk.keyStorePassword' property.
		//
		// Hint:
		//   - Check lab 6 code for examples
		//   - Getting java.security.KeyStoreException: Uninitialized keystore?
		//      Check out docs: http://docs.oracle.com/javase/6/docs/api/java/security/KeyStore.html
		
		List<X509Certificate> certificates = new ArrayList<X509Certificate>(4);
		for (String url: urls) {
			certificates.add(downloadCertificate(url));
		}
		
		// initialize keystore
		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		
		File storeFile = new File(System.getProperty("my.sk.keyStore"));
		if (!storeFile.exists()) {
			// create store if required
			store.load(null);
		} else {
			// loads keystore; otherwise
			FileInputStream in = new FileInputStream(storeFile);
			
			store.load(in, System.getProperty("my.sk.keyStorePassword").toCharArray());
			in.close();
		}
		
		// download certificates
		for (X509Certificate certificate: certificates) {
			store.setCertificateEntry(certificate.toString(), certificate);
		}
		
		// store keystore
		FileOutputStream out = new FileOutputStream(System.getProperty("my.sk.keyStore"));
		store.store(out, System.getProperty("my.sk.keyStorePassword").toCharArray());
		out.close();
		
		/*
		 * You can inspect the result by displaying the created keystore contents:
		 * 
		 * keytool -list -keystore <keystore-file>
		 */
	}

	/**
	 * Downloads certificate from this URL.
	 * 
	 * (1p)
	 */
	private static X509Certificate downloadCertificate(String url)
			throws GeneralSecurityException, IOException {
		// TODOdone: implement
		
		InputStream in = new URL(url).openStream();
		
		CertificateFactory factory = CertificateFactory.getInstance("X509");
		X509Certificate certificate = (X509Certificate) factory.generateCertificate(in);
		in.close();
		
		return certificate; // FIXMEdone
	}
}
