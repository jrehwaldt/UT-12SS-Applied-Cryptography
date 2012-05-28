package hw3;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RawContentVerifier;
import org.bouncycastle.util.encoders.Base64;

import common.Util;

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
		
		// TODOdone: Read server certificate from file set in 'my.server.certificate' property.
		FileInputStream in = new FileInputStream(System.getProperty("my.server.certificate"));
		CertificateFactory factory = CertificateFactory.getInstance("X509");
		X509Certificate certificate = (X509Certificate) factory.generateCertificate(in);
		in.close();
		
		// TODO: Read private key from file set in 'my.server.key' property (1p)
		
//		BufferedReader br = new BufferedReader(new FileReader(System.getProperty("my.server.key"))); 
//		KeyPair keyPair = (KeyPair) new PEMReader(br).readObject();
//		PrivateKey privateKey = keyPair.getPrivate();
//		BCRSAPrivateCrtKey bcPrivateKey = (BCRSAPrivateCrtKey) privateKey;
		
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		byte[] encodedKey = Util.readFile(System.getProperty("my.server.key"));
//		encodedKey = Arrays.copyOfRange(encodedKey, 28, encodedKey.length - 27);
		encodedKey = Arrays.copyOfRange(encodedKey, 32, encodedKey.length - 31);
		byte[] encoded = Base64.decode(encodedKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		
//		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//		byte[] encodedKey = Util.readFile(System.getProperty("my.server.key"));
//		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
//		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		
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
		
		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		
		File storeFile = new File(System.getProperty("javax.net.ssl.keyStore"));
		if (!storeFile.exists()) {
			// create store if required
			store.load(null);
		} else {
			// loads keystore; otherwise
			in = new FileInputStream(storeFile);
			
			store.load(in, System.getProperty("javax.net.ssl.keyStorePassword").toCharArray());
			in.close();
		}
		
		// remove old certificate if already existent
		String alias = "server";
		if (store.containsAlias("server")) {
			store.deleteEntry("server");
		}
		
		// import server certificate and private key
		store.setCertificateEntry(alias, certificate);
		
//		System.out.println(bcPrivateKey.getFormat());
//		System.out.println(new javax.crypto.EncryptedPrivateKeyInfo(privateKey.getEncoded()).getAlgName());
//		EncryptedPrivateKeyInfo encryptedInfo = new EncryptedPrivateKeyInfo(
////				AlgorithmIdentifier.getInstance("1.2.840.113549.1.8"),
////				AlgorithmIdentifier.getInstance("RSA"),
//				AlgorithmIdentifier.getInstance(NISTObjectIdentifiers.dsa_with_sha224),
//				privateKey.getEncoded());
//		System.out.println(encryptedInfo.getEncryptionAlgorithm().getAlgorithm().getId());
		
		// TODO comment in again
//		EncryptedPrivateKeyInfo encryptedInfo = new EncryptedPrivateKeyInfo(
//				privateKey.getEncoded());
//		store.setKeyEntry(
//				alias,
//				encryptedInfo.getEncoded(),
////				privateKey.getEncoded(),
//				new X509Certificate[] { certificate });
		
		// store keystore
		FileOutputStream out = new FileOutputStream(System.getProperty("javax.net.ssl.keyStore"));
		store.store(out, System.getProperty("javax.net.ssl.keyStorePassword").toCharArray());
		out.close();
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
		// TODOdone: Read SK certificates from file set in 'my.sk.keyStore' property (1p)
		FileInputStream in = new FileInputStream(System.getProperty("my.sk.keyStore"));
		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		
		store.load(in, System.getProperty("my.sk.keyStorePassword").toCharArray());
		in.close();
		return store; // FIXMEdone
	}

	/**
	 * Starts SSL server listening on port configured in 'my.server.pert' property.
	 * 
	 * (1p)
	 */
	private static SSLServerSocket startServer() throws IOException {
		// TODOdone: implement
		//
		// Hints:
		//   - See lab 20 code for examples
		System.out.println(" * Starting server..."); // Do not touch

		int port = Integer.valueOf(System.getProperty("my.server.port")); // FIXMEdone
		SSLServerSocket serverSocket = createServerSocket(port); // FIXMEdone

		System.out.println(" * Done, listening on port " + port + "..."); // Do not touch

		return serverSocket;
	}
	
	private static SSLServerSocket createServerSocket(int port) throws IOException {
		SSLServerSocketFactory socketFactory =
				(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		return (SSLServerSocket) socketFactory.createServerSocket(port);
	}

	/**
	 * Creates a new SignedData object from this byte array containing DER-encoded ContentInfo.
	 * 
	 * {@see http://tools.ietf.org/html/rfc5652#section-5}
	 * 
	 * (4p)
	 */
	private static SignedData toSignedData(byte[] contentInfoBytes) throws IOException {
		// TODOdone: implement
		//
		// Hints:
		//   - Re-create ContentInfo structure - you may want to use ASN1InputStream
		//   - Extract SignedData from ContentInfo
		//   - Most complex ASN.1 structures are internally just ASN1Sequences or ASN1OctetStrings

		/*
		 * Note that client is sending SignedData within ContentInfo structure. 
		 */
		ASN1InputStream in = new ASN1InputStream(contentInfoBytes);
		ASN1Encodable asn = in.readObject();
		
		ContentInfo contentInfo = ContentInfo.getInstance(asn);
		ASN1Encodable content = contentInfo.getContent();
		
		SignedData signedData = SignedData.getInstance(content);
		
		// TODO remove
		verifyByBCMeans(signedData, contentInfoBytes);
		
		return signedData; // FIXMEdone
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
		// TODOdone: implement
		
		ContentInfo contentInfo = signedData.getEncapContentInfo();
		ASN1Encodable asn1 = contentInfo.getContent();
		
		if (asn1 == null) {
			return null;
		}
		
		ASN1OctetString octet = (ASN1OctetString) asn1;
		return octet.getOctets(); // FIXMEdone
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
		// TODOdone: implement 
		// Throw an exception if 0 or 2+ certificates found.
		
		ASN1Set certificates = signedData.getCertificates();
		
		if (certificates.size() != 1) {
			throw new IllegalStateException("Unexpected number of certificates received");
		}
		
		ASN1Encodable asn1Certificate = certificates.getObjectAt(0);
		Certificate certificate = Certificate.getInstance(asn1Certificate);
		
		InputStream in = new ByteArrayInputStream(certificate.getEncoded());
		CertificateFactory factory = CertificateFactory.getInstance("X509");
		X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
		
		return cert; // FIXMEdone
	}

	/**
	 * Verifies this certificate against this store of trusted certificates.
	 * 
	 * (3p)
	 */
	private static boolean verifyCertificate(X509Certificate certificate, KeyStore keystore)
			throws GeneralSecurityException {
		// TODOdone: implement
		//
		// Hint:
		//   - You may want to use CertPathValidator class here
		// Build certificate path
		CertPathValidator validator = CertPathValidator.getInstance(
				CertPathValidator.getDefaultType(), "BC");
		
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(certificate);
		
		CertStore intermediateCertStore = CertStore.getInstance(
				"Collection",
				new CollectionCertStoreParameters(Arrays.asList(certificate)),
				"BC");
		
		PKIXBuilderParameters params = new PKIXBuilderParameters(keystore, selector);
		params.addCertStore(intermediateCertStore);
		params.setRevocationEnabled(false);
		
		CertPath path = CertPathBuilder.getInstance(
				CertPathBuilder.getDefaultType(), "BC").build(params).getCertPath();
		
		try {
			validator.validate(path, params);
		} catch (CertPathValidatorException e) {
			return false;
		}
		
		return true; // FIXMEdone
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
		
		// extract signature
		ASN1Set signerInfos = signedData.getSignerInfos();
		if (signerInfos.size() != 1) {
			throw new IllegalStateException("We expect exactly one SignerInfo for this task");
		}
		
		SignerInfo signerInfo = SignerInfo.getInstance(signerInfos.getObjectAt(0));
		byte[] verifyDigest = signerInfo.getEncryptedDigest().getOctets();
		byte[] data = getData(signedData);
		byte[] signedAttributes = signerInfo.getAuthenticatedAttributes().getEncoded();
		
//		String signatureAlgorithm = OIWObjectIdentifiers.sha1WithRSA.getId();
		String signatureAlgorithm = signerInfo.getDigestEncryptionAlgorithm().getAlgorithm().getId();
		
//		AlgorithmIdentifier id = signerInfo.getDigestAlgorithm();
//		AlgorithmIdentifier id2 = signerInfo.getDigestEncryptionAlgorithm();
//		ASN1Set digestAlgorithms = signedData.getDigestAlgorithms();
		// id1:              1.3.14.3.2.26
		// id2:              1.2.840.113549.1.1.1
		// digestAlgorithms: [1.3.14.3.2.26]
		// required:         1.3.14.3.2.29
		
		// verify data-only message digest, if signed attributes available
		byte[] verifyDataDigest = getMessageDigest(signerInfo);
		if (verifyDataDigest != null) {
			byte[] dataDigest = computeDigest(signerInfo, data);
			
			if (!Arrays.equals(dataDigest, verifyDataDigest)) {
				return false;
			}
		}
		
		// verify content-type of Signed Data
		ASN1ObjectIdentifier verifyContentType = getContentType(signerInfo);
		if (verifyContentType != null) {
			ASN1ObjectIdentifier contentType = signedData.getEncapContentInfo().getContentType();
			
			if (!contentType.equals(verifyContentType)) {
				return false;
			}
		}
		
		// compute digest of signed attributes
		byte[] signedAttributesDigest = computeDigest(signerInfo, signedAttributes);
		
		// initialize signature
		Signature signature = Signature.getInstance(OIWObjectIdentifiers.sha1WithRSA.getId(), "BC");
		signature.initVerify(certificate.getPublicKey());
		
		// add data
		signature.update(data);
		signature.update(signedAttributesDigest);
		
		// verify
		boolean verified = signature.verify(verifyDigest);
		
		// TODO try two ways of signature checking
		byte[] fullDigest = computeDigest(signerInfo, data, signedAttributesDigest);
		signature.update(fullDigest);
		boolean verified2 = signature.verify(verifyDigest);
		
		fullDigest = computeDigest(signerInfo, data, signedAttributes);
		signature.update(fullDigest);
		boolean verified3 = signature.verify(verifyDigest);
		
		signature.update(data);
		signature.update(signedAttributes);
		boolean verified4 = signature.verify(verifyDigest);
		
		// 
		// Fix for "Illegal key size or default parameters"
		// @see http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
		// 
		Cipher cipher = Cipher.getInstance(signatureAlgorithm, "BC");
		cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
		cipher.update(fullDigest);
		byte[] encryptedFullDigest = cipher.doFinal();
		System.out.println(encryptedFullDigest.length);
		
		boolean verified5 = Arrays.equals(verifyDigest, encryptedFullDigest);
		
		// XXX
		System.out.println(signerInfo.getEncryptedDigest().getEncoded().length);
		System.out.println(signerInfo.getEncryptedDigest().getOctets().length);
		
		char[] encode = Hex.encodeHex(signerInfo.getEncryptedDigest().getOctets());
		String hexVerifyDigest = new String(encode);
		System.out.println(hexVerifyDigest);
		System.out.println(hexVerifyDigest.length());
		// XXX
		
		// YYY
		boolean verified7 = false;
//		try {
//			verified7 = true;
//			InputStream is = new ByteArrayInputStream(data);
//			DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();
//			CMSSignedDataParser parser = new CMSSignedDataParser(digestProvider, signedData.getEncoded());
//			CMSTypedStream signedContent = parser.getSignedContent();
//			signedContent.drain();
//			
//			Store certStore = parser.getCertificates();
//			SignerInformationStore signers = parser.getSignerInfos();
//			
//			Collection c = signers.getSigners(); 
//			Iterator it = c.iterator();
//			while(it.hasNext()) {
//				SignerInformation signer = (SignerInformation)it.next();  
//				Collection certCollection = certStore.getMatches(signer.getSID());
//				
//				Iterator certIt = certCollection.iterator();
//				X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();
//				
//				SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certHolder);
//				if (!signer.verify(verifier)) {
//					verified7 = false;
//				} else {
//					System.out.println("verify success" );
//				}
//			}
//			
//		} catch (CMSException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (OperatorCreationException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		try {
//			JcaSimpleSignerInfoVerifierBuilder signerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
//			signerInfoVerifierBuilder.setProvider("BC");
//			SignerInformationVerifier signerInformationVerifier = signerInfoVerifierBuilder.build(certificate);
//			ContentVerifier contentVerifier = signerInformationVerifier.getContentVerifier(signerInfo.getDigestEncryptionAlgorithm(), signerInfo.getDigestAlgorithm());
////			verified7 = contentVerifier.verify(verifyDigest);
//			
//			
//			DigestCalculator calc = signerInformationVerifier.getDigestCalculator(signerInfo.getDigestAlgorithm());
//			OutputStream digOut = calc.getOutputStream();
//			digOut.write(data);
//			digOut.close();
//			
//			byte[] resultDigest = calc.getDigest();
//			
//			if (contentVerifier instanceof RawContentVerifier) {
//				RawContentVerifier rawVerifier = (RawContentVerifier) contentVerifier;
//
////				String encName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(signerInfo.getDigestEncryptionAlgorithm());
////				if (encName.equals("RSA")) {
//					DigestInfo digInfo = new DigestInfo(signerInfo.getDigestAlgorithm(), resultDigest);
//					
//					verified7 = rawVerifier.verify(digInfo.getEncoded(ASN1Encoding.DER), resultDigest);
////				}
//				verified7 = rawVerifier.verify(verifyDataDigest, resultDigest);
//				
//				CMSSignedData xxx = new CMSSignedData(signedData.getEncoded());
//				SignerInformationStore store = xxx.getSignerInfos();
////				new CMSProcessableByteArray(null, signer.getSignature())
//				Collection signers = store.getSigners();
//				System.out.println(signers.size());
//			}
//			
//		} catch (OperatorCreationException e) {
//			e.printStackTrace();
//		} catch (CMSException e) {
//			e.printStackTrace();
//		}
//		
//		// YYY
		
		
		cipher = Cipher.getInstance(signatureAlgorithm, "BC");
		cipher.init(Cipher.DECRYPT_MODE, certificate.getPublicKey());
//		cipher.update(verifyDigest);
//		byte[] decryptedVerifyDigest = cipher.doFinal();
//		
//		boolean verified6 = Arrays.equals(decryptedVerifyDigest, fullDigest);
		boolean verified6 = false;
		
		if (verified || verified2 || verified3 || verified4 || verified5 || verified6 || verified7) {
			System.out.println("YEAAAAAAAAHHHHHHHHHHHHHH!!!");
		}
		
		return verified; // FIXME
	}
	
	private static byte[] computeDigest(SignerInfo signerInfo, byte[]... data) throws NoSuchAlgorithmException {
		
		MessageDigest digest = MessageDigest.getInstance(
				signerInfo.getDigestAlgorithm().getAlgorithm().getId());
		
		for (byte[] d: data) {
			digest.update(d);
		}
		return digest.digest();
	}
	
	private static final ASN1ObjectIdentifier OID_MESSAGE_DIGEST = new ASN1ObjectIdentifier("1.2.840.113549.1.9.4");
	private static final ASN1ObjectIdentifier OID_CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.3");
	
	private static byte[] getMessageDigest(SignerInfo signerInfo) {
		
		@SuppressWarnings("unchecked")
		Enumeration<DERSequence> attributes = signerInfo.getAuthenticatedAttributes().getObjects();
		while (attributes.hasMoreElements()) {
			DERSequence sequence = attributes.nextElement();
			
			if (sequence.size() != 2) {
				throw new IllegalStateException("Attribute malformed");
			}
			
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
			
			if (!OID_MESSAGE_DIGEST.equals(oid)) {
				continue;
			}
			
			DERSet messageDigestSequence = (DERSet) sequence.getObjectAt(1);
			DEROctetString messageDigest = (DEROctetString) messageDigestSequence.getObjectAt(0);
			
			return messageDigest.getOctets();
		}
		
		throw null;
	}
	
	private static ASN1ObjectIdentifier getContentType(SignerInfo signerInfo) {
		
		@SuppressWarnings("unchecked")
		Enumeration<DERSequence> attributes = signerInfo.getAuthenticatedAttributes().getObjects();
		while (attributes.hasMoreElements()) {
			DERSequence sequence = attributes.nextElement();
			
			if (sequence.size() != 2) {
				throw new IllegalStateException("Attribute malformed");
			}
			
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) sequence.getObjectAt(0);
			
			if (!OID_CONTENT_TYPE.equals(oid)) {
				continue;
			}
			
			DERSet oidSeq = (DERSet) sequence.getObjectAt(1);
			ASN1ObjectIdentifier contentType = (ASN1ObjectIdentifier) oidSeq.getObjectAt(0);
			
			return contentType;
		}
		
		throw null;
	}
	
	private static void verifyByBCMeans(SignedData signedData,
			byte[] contentInfoBytes)
	throws IOException {
		// TODO remove whole method
		try {
			CMSSignedData xxx = new CMSSignedData(contentInfoBytes);
			SignerInformationStore store = xxx.getSignerInfos();
			SignerInformation info = (SignerInformation) store.getSigners().iterator().next();
			
			JcaSimpleSignerInfoVerifierBuilder signerInfoVerifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
			signerInfoVerifierBuilder.setProvider("BC");
			SignerInformationVerifier verifier = signerInfoVerifierBuilder.build(getCertificate(signedData).getPublicKey());
			
			System.out.println(info.verify(verifier));
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}