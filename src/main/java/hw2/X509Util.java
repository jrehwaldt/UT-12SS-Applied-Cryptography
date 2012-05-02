package hw2;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/*
 * Fix all the TODOdone's. Follow the Javadoc.
 * 
 * You are *not* allowed to change method signatures.
 */
@SuppressWarnings("deprecation")
public final  class X509Util {
	/**
	 * Extracts first CRL distribution URL from this X.509 certificate.
	 */
	public static String getCrlUrl(X509Certificate certificate)
			throws IOException {
		// TODOdone: implement.
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
		//        SEQUENCE { -- distributionPoint
		//           [0] { -- fullName
		//               [0] { -- uniformResourceIdentifier
		//                   [6] 'some-url-here' -- CRL URL you need
		//               }
		//           }
		//        }
		//    }
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
		
		byte[] extension = certificate.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
		if (extension == null) {
			return null;
		}
		
		ASN1Object derObj = X509ExtensionUtil.fromExtensionValue(extension);
		
		CRLDistPoint distributionPoint = CRLDistPoint.getInstance(derObj);
		for (DistributionPoint dp : distributionPoint.getDistributionPoints()) {
			DistributionPointName name = dp.getDistributionPoint();
			// Look for URIs in fullName
			if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
				GeneralName[] generalNames = GeneralNames.getInstance(name.getName()).getNames();
				// Look for an URI
				for (int j = 0; j < generalNames.length; j++) {
					if (generalNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
						String url = DERIA5String.getInstance(generalNames[j].getName()).getString();
						return url;
					}
				}
			}
		}
		
		return null;
	}

	/**
	 * Extracts OCSP service URL from this X.509 certificate.
	 */
	public static String getOcspUrl(X509Certificate certificate)
			throws IOException {
		// TODOdone: implement.
		//
		// Once you have implemented getCrlUrl(X509Certificate) method, this one should be easy
		// to complete. The logic behind extracting values is the same, only the structures are
		// slightly different.
		//
		// Check out http://tools.ietf.org/html/rfc5280#section-4.2.2.1 for details.
		
		byte[] extension = certificate.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
		if (extension == null) {
			return null;
		}
		
		ASN1Object derObj = X509ExtensionUtil.fromExtensionValue(extension);
		
		AuthorityInformationAccess info = AuthorityInformationAccess.getInstance(derObj);
		for (AccessDescription description : info.getAccessDescriptions()) {
			if (description.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
				GeneralName generalName = description.getAccessLocation();
				if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
					String url = DERIA5String.getInstance(generalName.getName()).getString();
					return url;
				}
			}
		}
		
		return null;
	}

	/**
	 * Reads X.509 certificate from this input stream.
	 */
	public static X509Certificate readCertificate(InputStream in)
			throws CertificateException, IOException {
		// TODOdone: implement.
		//
		// Challenge: make it one-liner.
		X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
		
		return certificate;
	}

	/**
	 * Reads X.509 CRL object from this input stream.
	 */
	public static X509CRL readCrl(InputStream in)
			throws CertificateException, CRLException, IOException {
		// TODOdone: implement.
		//
		// Challenge: make it one-liner.
		X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
		return crl;
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
		// TODOdone: implement.
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

		// TODOdone: verify certificate validity issuer
		if (!certificate.getIssuerDN().equals(issuerCertificate.getSubjectDN())) {
			throw new CertificateException("Certificate issuer doesn't match");
		}
		score += 1; // I may change these while reviewing your code.
		
		// TODOdone: verify certificate validity dates
		certificate.checkValidity();
		score += 1;

		// TODOdone: verify public key signature
		try {
			certificate.verify(issuerCertificate.getPublicKey());
		} catch (SignatureException e) {
			throw new CertificateException("Certificate's signature does not match public key", e);
		} catch (InvalidKeyException e) {
			throw new CertificateException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new CertificateException(e);
		} catch (NoSuchProviderException e) {
			throw new CertificateException(e);
		}
		score += 1;
		
		// TODOdone: check certificate status via OCSP. report status code in case of failure.
		//
		// It is okay to use some deprecated BouncyCastle classes here, if needed. These will make
		// your life much easier.
		//
		// Check lab 7 code for examples.
		try {
			// Compose certificate ID for OCSP request
			// See http://www.bouncycastle.org/docs/docs1.6/org/bouncycastle/ocsp/CertificateID.html
			CertificateID certificateId = new CertificateID(
					CertificateID.HASH_SHA1,
					issuerCertificate,
					certificate.getSerialNumber());
			
			// Create OCSP request
			OCSPReqGenerator ocspRequestGenerator = new OCSPReqGenerator();
			ocspRequestGenerator.addRequest(certificateId);
			OCSPReq ocspRequest = ocspRequestGenerator.generate();
			
			// Send OCSP request and receive response.
			// Service URL is available from OCSP extension of the certificate being verified.
			byte[] ocspRequestBytes = ocspRequest.getEncoded();
			
			// Third argument should be the URL of OCSP service.
			// This URL is available from OCSP extension of the certificate being verified.
			URL url = new URL(getOcspUrl(certificate));
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type", "application/ocsp-request");
			connection.setRequestProperty("Content-Length", Integer.toString(ocspRequestBytes.length));
			connection.connect();
			
			OutputStream out = connection.getOutputStream();
			out.write(ocspRequestBytes);
			out.flush();
			out.close();
			System.out.println("OCSP request HTTP code: " + connection.getResponseCode());
			
			InputStream in = connection.getInputStream();
			OCSPResp ocspResponse = new OCSPResp(in);
			System.out.println("OCSP response status: " + ocspResponse.getStatus());
			
			if (ocspResponse.getStatus() != 0) {
				throw new CertificateException("OCSP response not successful: " + ocspResponse.getStatus());
			}
			
			/*
			 * Note that response status is not the same as certificate status.
			 * 
			 * Response status is the status of OCSP communication (successful,
			 * failed, etc.).
			 * 
			 * Certificate status is only available if OCSP communication succeeded
			 * (see above) and shows if the certificate was revoked.
			 * 
			 * See also: http://tools.ietf.org/html/rfc2560#section-4.2.1
			 */
	
			BasicOCSPResp ocspBasicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
			SingleResp ocspSignleResponse = ocspBasicResponse.getResponses()[0];
			System.out.println("Certificate: " + ocspSignleResponse.getCertID().getSerialNumber());
			if (ocspSignleResponse.getCertStatus() == null) {
				System.out.println("OCSP check passed");
			} else {
				throw new CertificateException("OCSP check failed, status: " + ocspSignleResponse.getCertStatus());
			}
		} catch (IOException e) {
			throw new CertificateException("Downloading OCSP file failed: " + e.getMessage(), e);
		} catch (OCSPException e) {
			throw new CertificateException(e);
		}
		score += 3;
		
		// TODOdone: verify CRL signature and check if certificate was revoked
		try {
			// CRL signature should be verified to ensure CRL's consistency and authenticity.
			crl.verify(issuerCertificate.getPublicKey());
	
			// Finally, search a certificate being verified in revoked certificates list.
			if (crl.getRevokedCertificate(certificate) == null) {
				System.out.println("CRL check passed");
			} else {
				throw new CertificateException("CRL: Certificate was revoked");
			}
		} catch (CRLException e) {
			throw new CertificateException(e);
		} catch (InvalidKeyException e) {
			throw new CertificateException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new CertificateException(e);
		} catch (NoSuchProviderException e) {
			throw new CertificateException(e);
		} catch (SignatureException e) {
			throw new CertificateException("CRL's signature does not match public key", e);
		}
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
		// TODOdone: implement.
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
		
		// TODOdone: verify trusted certificate public key signature
		// = self-signed
		trustedCertificate.verify(trustedCertificate.getPublicKey());
		score += 1;
		
		// TODOdone: create a set of trust anchors.
		// Create the trust anchors (set of root CA certificates)
		TrustAnchor anchor = new TrustAnchor(trustedCertificate, null);
		
		// TODOdone: create a list of all certificates being verified.
		// Create the selector that specifies the starting certificate
		X509CertSelector selector = new X509CertSelector();
		selector.setSerialNumber(certificate.getSerialNumber());
		selector.setIssuer(certificate.getIssuerX500Principal().getEncoded());
//		selector.setCertificate(certificate);
		
		// TODOdone: create a certificate store.
		// Specify a list of intermediate certificates
		CertStore intermediateCertStore = CertStore.getInstance(
				"Collection",
				new CollectionCertStoreParameters(
						Arrays.asList(
								intermediateCertificates[0],
								intermediateCertificates[1],
								trustedCertificate,
								certificate)),
				"BC");

		// TODOdone: Build the certificate chain.
		// TODOdone: Verify the certificate chain.
		// Configure the PKIX certificate builder algorithm parameters
		PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(
				Collections.singleton(anchor),
				selector);
		
		// Disable CRL checks (this is done manually as additional step)
		pkixParams.setRevocationEnabled(false);
		pkixParams.addCertStore(intermediateCertStore);

		// Build the certification chain
		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
		
		try {
			PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(pkixParams);
			System.out.println("Certificate path length: " + result.getCertPath().getCertificates().size());
		} catch (Exception e) {
			throw new CertificateException(e);
		}
		score += 2;
		score += 4; // verification took place if building was successful
		
		return score;
	}

	/**
	 * Encoded this X.509 certificate using DER and writes the result to this output stream.
	 */
	public static void writeDer(OutputStream out, X509Certificate certificate)
			throws CertificateEncodingException, IOException {
		// TODOdone: implement
		out.write(certificate.getEncoded());
	}

	/**
	 * Encoded this X.509 certificate using PEM rules and writes the result to this output stream.
	 */
	public static void writePem(OutputStream out, X509Certificate certificate)
			throws CertificateEncodingException, IOException {
		// TODOdone: implement.
		//
		// Hint: `org.bouncycastle.util.io.pem.*` package may be useful.
		//
		// Note that you will get penalty (2p) for using `sun.misc.*` classes directly!
		
		PemObjectGenerator pemObject = new PemObject("CERTIFICATE", certificate.getEncoded());
		
		PemWriter writer = new PemWriter(new OutputStreamWriter(out));
		writer.writeObject(pemObject);
		writer.flush();
	}


	// Jan: there's a helper method already in X509ExtensionUtils or so...
	@SuppressWarnings("unused")
	private static ASN1Encodable toAsn1Object(byte[] encoded)
			throws IOException {
		return new ASN1InputStream(encoded).readObject(); 
	}
}
