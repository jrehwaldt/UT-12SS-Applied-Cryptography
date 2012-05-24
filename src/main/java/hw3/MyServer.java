package hw3;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*
 * To run this server, you will need a self-signed certificate.
 * 
 * Refer to lab 6 for examples on how to create one using OpenSSL. Make sure to set
 * certificate common name (CN) to 'localhost' (or a valid IP/hostname if you are running
 * the server elsewhere), otherwise you may have problems with establishing certificate
 * trust on client side.
 * 
 * Make sure all the configuration properties are read from configuration file -- see below.
 * 
 * You will get penalty (2p) for every hard-coded configuration *value*,
 * but it is still okay to hard-code configuration *key names*.
 * 
 * You are allowed to use BouncyCastle provider and PKIX libraries for this task.
 * No other libraries are allowed.
 */

/**
 * Runs HTTPS server.
 * 
 * This server accepts client requests via HTTPS. Client requests should contain
 * CMS ContentInfo with SignedData structure and use POST method to send this data.
 * Request format is:
 * 
 * <pre>
 *     HTTP headers -- do not bother about those
 *     
 *     ContentInfoHex={hex-encoded-ConetntInfo}
 * </pre>
 * 
 * Server then parses received ContentInfo, verifies signature and sends response to client.
 * This response contains the message the client has signed, and the signature verification
 * result. response format is:
 * 
 * <pre>
 *     HTTP headers -- hard-coded for simplicity, do not bother about those
 *     
 *     Data you've signed: {data}
 *     Signature verified -OR- Signature NOT verified
 * </pre>
 * 
 * Client signature is expected to be done using Estonian ID card. For verification,
 * SK certificates are used. These certificates should be imported beforehand and saved to
 * local keystore -- see {@link MyCertificateImporter} class for details on how to import
 * these certificates.
 * 
 * Server configuration parameters are loaded from Java properties file, make sure to run
 * {@code MyConf.load()} before attempting to access configuration properties --
 * check {@link MyConf} class for details.
 * 
 * You need to create a configuration file (recommended path: hw3.properties) with at least
 * these configuration options set:
 * <ul>
 *   <li>{@code javax.net.ssl.keyStore} -- keystore file path (will be created automagically)</li>
 *   <li>{@code javax.net.ssl.keyStorePassword} -- password to access keystore</li>
 *   <li>{@code my.server.certificate} -- SSL certificate file path (you need to create that)</li>
 *   <li>{@code my.server.key} -- private key file path (you need to create that)</li>
 *   <li>{@code my.server.port} -- port to listen on, set to 4435 if unsure</li>
 * </ul>
 * 
 * (all tasks: 22p)
 */
public class MyServer {
	/**
	 * Runs HTTPS server.
	 */
	public static void main(String[] args) throws Exception {
		MyConf.load(); // Loads configuration properties

		Security.addProvider(new BouncyCastleProvider());

		// Initialize keystore for SSL context
		initSslKeystore();

		// Load keystore to verify client signatures
		KeyStore keystore = getAppKeystore();

		SSLServerSocket serverSocket = startServer();
		// Run server loop (inefficient, do not use in production)
		while (true) {
			OutputStream out = null;
			SSLSocket clientSocket = null;

			try {
				// Accept client connection
				clientSocket = (SSLSocket) serverSocket.accept();
				System.out.println(" * Client connected: " + clientSocket.getInetAddress());

				// Receive message from client
				BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				String line;
				while ((line = reader.readLine()) != null) {
					if (line.startsWith("ContentInfoHex")) {
						line = line.split("=")[1];
						break;
					}
				}
				// `line` variable should now contain hex-encoded ContentInfo object.

				// Extract SignedData and raw data
				SignedData signedData = toSignedData(Util.fromHexString(line));
				byte[] data = getData(signedData);

				// Extract and verify client certificate
				X509Certificate certificate = getCertificate(signedData);
				boolean isCertificateVerified = verifyCertificate(certificate, keystore);

				// Verify signature
				boolean isSignatureVerified = verifySignature(signedData, certificate);

				boolean isVerified = isSignatureVerified && isCertificateVerified;

				// Reply to client
				out = clientSocket.getOutputStream();
				BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out)); 
				writer.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
				writer.write("Data you've signed: " + new String(data));
				writer.write("\nSignature " + (isVerified ? "" : "NOT ") + "verified");
				writer.flush();	
			} catch (Exception e) {
				e.printStackTrace();

				// You may want to disable this once the server has started successfully
				System.exit(1);
			}

			// End connection
			if (out != null) {
				out.close();
			}
			if (clientSocket != null) {
				clientSocket.close();
			}
			System.out.println("Connection closed.");
		}
	}

	/**
	 * Creates a local keystore with server key and certificate to use for SSL connections.
	 * 
	 * For that, server certificate and private key are read from PEM-files (configured as
	 * 'my.server.certificate' and 'my.server.key' respectively), and added to keystore.
	 * 
	 * Keystore is saved to file configured in 'javax.net.ssl.keyStore' property.
	 * 
	 * Keystore password is set in 'javax.net.ssl.keyStorePassword' property.
	 * 
	 * (5p)
	 */
	private static void initSslKeystore() throws GeneralSecurityException, IOException {
		/*
		 * In previous tasks we were reading server certificates from Java keystore.
		 * In real life, certificates are more often stored in separate files, PEM-encoded.
		 * Here we will import the certificate from the file and create a temporary keystore
		 * to be used by server.
		 * 
		 * Note that both private key and certificate should be in the same format as generated
		 * by OpenSSL -- PEM-encoded. If you store them in any other format, your code will
		 * most likely fail the tests.
		 */

		// TODO: Read server certificate from file set in 'my.server.certificate' property.

		// TODO: Read private key from file set in 'my.server.key' property (1p)

		// TODO: Create a new Java keystore
		//   - import server certificate
		//   - import private key
		//   - save to file set in 'javax.ssl.net.keyStore' property
		//
		// This keystore will be later read automatically by system internals
		// to create a SSLContext for HTTPS connection.
		//
		// Key password should be set in 'javax.net.ssl.keyStorePassword' property.
		//
		// Key alias may be just 'server'.
		//
		// Hints:
		//   - Check out http://docs.oracle.com/javase/6/docs/api/java/security/KeyStore.html
	}

	/**
	 * Loads SK certificates from local keystore -- file path configured in
	 * 'my.sk.keyStore' property.
	 * 
	 * Keystore password is set in 'my.sk.keyStorePassword' property.
	 * 
	 * SK certificates must be imported to this keystore already --
	 * see {@link MyCertificateImporter} for details.
	 * 
	 * (1p)
	 */
	private static KeyStore getAppKeystore() throws GeneralSecurityException, IOException {
		// TODO: Read SK certificates from file set in 'my.sk.keyStore' property (1p)
		return null; // FIXME
	}

	/**
	 * Starts SSL server listening on port configured in 'my.server.pert' property.
	 * 
	 * (1p)
	 */
	private static SSLServerSocket startServer() throws IOException {
		// TODO: implement
		//
		// Hints:
		//   - See lab 20 code for examples
		System.out.println(" * Starting server..."); // Do not touch

		int port = 0; // FIXME
		SSLServerSocket serverSocket = null; // FIXME

		System.out.println(" * Done, listening on port " + port + "..."); // Do not touch

		return serverSocket;
	}

	/**
	 * Creates a new SignedData object from this byte array containing DER-encoded ContentInfo.
	 * 
	 * {@see http://tools.ietf.org/html/rfc5652#section-5}
	 * 
	 * (4p)
	 */
	private static SignedData toSignedData(byte[] contentInfoBytes) throws IOException {
		// TODO: implement
		//
		// Hints:
		//   - Re-create ContentInfo structure - you may want to use ASN1InputStream
		//   - Extract SignedData from ContentInfo
		//   - Most complex ASN.1 structures are internally just ASN1Sequences or ASN1OctetStrings

		/*
		 * Note that client is sending SignedData within ContentInfo structure. 
		 */
		return null; // FIXME
	}

	/**
	 * Extracts actual raw data that the client sent to signing procedure.
	 * 
	 * This data (if provided), can be found in EncapsulatedContentInfo strucutre
	 * inside this SignedData. 
	 * 
	 * (1p)
	 */
	private static byte[] getData(SignedData signedData) {
		// TODO: implement
		return null; // FIXME
	}

	/**
	 * Extracts client certificate from this SignedData.
	 * 
	 * This certificate can be used for signature verification.
	 * 
	 * @throws CertificateException if certificate parsing failed, or 0 or 2+ certificates found.
	 * 
	 * (3p)
	 */
	private static X509Certificate getCertificate(SignedData signedData)
			throws CertificateException, IOException {
		// TODO: implement 
		// Throw an exception if 0 or 2+ certificates found.
		return null; // FIXME
	}

	/**
	 * Verifies this certificate against this store of trusted certificates.
	 * 
	 * (3p)
	 */
	private static boolean verifyCertificate(X509Certificate certificate, KeyStore keystore)
			throws GeneralSecurityException {
		// TODO: implement
		//
		// Hint:
		//   - You may want to use CertPathValidator class here
		// Build certificate path
		return false; // FIXME
	}

	/**
	 * Verifies this signed data signature.
	 * 
	 * Due to limitations of EstEID cards, only supported signature algorithm is RSA
	 * and only supported digest algorithm is SHA1.
	 * 
	 * (4p)
	 */
	private static boolean verifySignature(SignedData signedData, X509Certificate certificate)
			throws GeneralSecurityException, IOException {
		// TODO: implement

		/*
		 * SignedData, as follows from the name, contains data signature,
		 * but extracting and especially verifying that is not as simple as it may feel.
		 * 
		 * Signature itself is stored within SignerInfo structure, as SignedData is designed
		 * may contain multiple SignerInfos and therefore also multiple signatures.
		 * For this task, it is assumed that there is exactly one SignerInfo present.
		 * It is okay to throw an exception now if there are none or multiple SignerInfos
		 * found, but in real life you would have to handle these cases properly.
		 * 
		 * Check RFC section about SignerInfo: http://tools.ietf.org/html/rfc5652#section-5.3
		 * 
		 * In our case, signature was created using private key from EstEID card, and you
		 * will need public key to verify that. For this task, client should add certificate
		 * to SignedData structure it is sending to server -- see MyClient class, but again,
		 * in real life this is not always the case: certificate set in SignedData is optional.
		 * 
		 * Most important, the data being signed is *not* just the raw data the client has
		 * submitted to signing procedure. Read RFC section about SignerInfo carefully (see
		 * link above) and make sure you understand what exactly is signed, and what part of
		 * SignedData should you use for signature verification.
		 * 
		 * Note that signature is sometimes referred as 'encrypted digest'.
		 * 
		 * Also note that you may get 'java.security.InvalidKeyException: Wrong key usage'
		 * exception if trying to verify the signature using certificate from EstEID card.
		 * Seems that it is a bug on EstEID side and the signing certificate is not allowing
		 * the corresponding key to be used for signatures. As a workaround, you way want to
		 * verify signature using public key from the certificate, not the certificate itself --
		 * in this case, certificate extension validation will be skipped.
		 */
		return false; // FIXME
	}
}
