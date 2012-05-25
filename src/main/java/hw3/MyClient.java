package hw3;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import common.Util;

/*
 * You are allowed to use BouncyCastle provider and PKIX libraries for this task.
 * No other libraries are allowed.
 */

/**
 * Runs HTTPS client -- sends request to HTTPS server and receives the response.
 * 
 * See {@link MyServer} documentation for request and response format description.
 * 
 * This code tries do demonstrate how would Estonian ID card signatures integrate with
 * some existing standard. For illustration purposes, some small piece of data is signed
 * using EstEID card, packed into CMS SignedData structure and sent to server for parsing
 * and verification.
 * 
 * Instead of simple signing demonstrated on previous labs, where we were just happy to
 * get byte array containing a signature value, this code uses more complex approach to
 * integrate EstEID signing mechanism with existing Java and BouncyCastle cryptographic
 * routines. One of your task will be just 'hiding' all the EstEID magic inside signature
 * provider -- see {@link MyEstEidSigner} class.
 * 
 * (all tasks: 8p)
 */
public class MyClient {
	public static void main(String[] args) throws Exception {
		if (args.length < 1) {
			System.out.println("Usage: java " + MyClient.class + " <data-to-sign>");
			System.exit(1);
		}

		MyConf.load(); // Loads configuration properties

		Security.addProvider(new BouncyCastleProvider());

		byte[] data = args[0].getBytes();

		ContentInfo contentInfo = createSignedData(data); 

		// Create SSLContext to use for HTTPS connection
		KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		trustStore.load(
				new FileInputStream(System.getProperty("javax.net.ssl.keyStore")),
				System.getProperty("javax.net.ssl.keyStorePassword").toCharArray());

		TrustManagerFactory tmFactory = TrustManagerFactory.getInstance(
				TrustManagerFactory.getDefaultAlgorithm());
		tmFactory.init(trustStore);

		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(null, tmFactory.getTrustManagers(), null);

		// Initialize HTTPS connection
		// Make sure to set 'my.server.port' configuration property and run MyConf.load().
		System.out.println(" * Sending data to server...");

		URL url = new URL("https://localhost:" + System.getProperty("my.server.port"));
		HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
		connection.setDoOutput(true);
		connection.setDoInput(true);
		connection.setSSLSocketFactory(sslContext.getSocketFactory());

		// Send SignedData to server
		OutputStream out = connection.getOutputStream();
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
		writer.write("ContentInfoHex=" + Util.toHexString(contentInfo.getEncoded()));
		writer.newLine();
		writer.flush();

		// Receive response from server
		InputStream in = connection.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		String line;
		while ((line = reader.readLine()) != null) {
			System.out.println(line);
		}

		System.out.println("All done.");
	}

	/**
	 * Signs this data using EstEID card, and build a SignedData structure to keep the result.
	 * 
	 * This SignedData also contains one SignerInfo and one certificate -- signing certificate
	 * form EstEID card. This certificate will be used for signature verification where card is
	 * not accessible (server, other application, etc.)
	 * 
	 * {@see http://tools.ietf.org/html/rfc5652#section-5}
	 * 
	 * (8p)
	 */
	private static ContentInfo createSignedData(byte[] data)
			throws CMSException, GeneralSecurityException, IOException, OperatorCreationException  {
		// TODOdone: implement
		//
		// Resulting SignedData must contain:
		//   - Initial data
		//   - One (signing) certificate from EstEID card used for signing
		//   - One SignerInfo structure with signature parameters
		//
		// Note that signature computation for SignedData structure is different from 'simple'
		// signing we've done before. Check MyServer.verifySignature() method comments for details.
		//
		// Hints:
		//   - Check lab 15 code for some examples
		//   - Use your implemented MyEstEidSigner class as signature provider (signer)
		//   - Use org.bouncycastle.cert.X509CertificateHolder class to store encoded certificates
		
		MyEstEidSigner contentSigner = new MyEstEidSigner();
		X509Certificate certificate = contentSigner.getCertificate();
		
		// create generator
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		
		// add signer info
		DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();
		
		SignerInfoGenerator signerInfoGenerator =
				new JcaSignerInfoGeneratorBuilder(digestProvider).build(contentSigner, certificate);
		generator.addSignerInfoGenerator(signerInfoGenerator);
		
		// add certificate
		Store certs = new JcaCertStore(Arrays.asList(certificate));
		generator.addCertificates(certs);
		
		// add data; generate ContentInfo
		CMSTypedData typedData = new CMSProcessableByteArray(data);
		ContentInfo contentInfo = generator.generate(typedData, true).toASN1Structure();
		
		return contentInfo;
		
		/*
		 * You can debug the resulting ASN.1 structure by writing it DER-encoded to a file
		 * and then inspecting the file contents with `dumpasn1` utility.
		 * 
		 * Alternatively, you cat use Util.toAsn1String(byte[]) to print the structure
		 * contents. Make sure to comment out or remove this debugging output when submitting
		 * the task -- you will get penalty (1p) if you don't.
		 */
	}
}
