package lab07;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;

/*
 * Demonstrates how to verify X.509 certificate revocation status via OCSP.
 * 
 * OCSP strucutres are described in RFC 2560: X.509 Internet PKI OCSP
 * (http://tools.ietf.org/html/rfc2560). Here is a simplified OCSP request:
 * 
 * OCSPRequest {
 *     TBSRequest {
 *         version
 *         Request[] {
 *             CertID {
 *                 hashLagorithm
 *                 issuerNameHash
 *                 issuerKeyHash
 *                 serialNumber
 *             }
 *         }
 *     }
 *     Signature {
 *         signatureAlgorithm
 *         signature
 *     }
 * }
 * 
 * (some optional fields skipped)
 * See also: http://tools.ietf.org/html/rfc2560#section-4.1.1
 */

public class OcspDemo {
	public static void main(String[] args) throws Exception {
		// We will need BouncyCastle provider to create OCSP request
		Security.addProvider(new BouncyCastleProvider());

		InputStream in = null;
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

		// First argument should be the path to the certificate file being verified.
		in = new FileInputStream(args[0]);
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);

		// Second parameter should be the path to issuer certificate file.
		in = new FileInputStream(args[1]);
		X509Certificate issuerCertificate =
				(X509Certificate) certificateFactory.generateCertificate(in);

		// Compose certificate ID for OCSP request
		// See http://www.bouncycastle.org/docs/docs1.6/org/bouncycastle/ocsp/CertificateID.html
		CertificateID certificateId = new CertificateID(
				CertificateID.HASH_SHA1, issuerCertificate, certificate.getSerialNumber());

		// Create OCSP request
		OCSPReqGenerator ocspRequestGenerator = new OCSPReqGenerator();
		ocspRequestGenerator.addRequest(certificateId);
		OCSPReq ocspRequest = ocspRequestGenerator.generate();

		// Send OCSP request and receive response.
		// Service URL is available from OCSP extension of the certificate being verified.
		byte[] ocspRequestBytes = ocspRequest.getEncoded(); 

		// Third argument should be the URL of OCSP service.
		// This URL is available from OCSP extension of the certificate being verified.
		URL url = new URL(args[2]);
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

		in = connection.getInputStream();
		OCSPResp ocspResponse = new OCSPResp(in);
		System.out.println("OCSP response status: " + ocspResponse.getStatus());

		/*
		 * Note that response status is not the same as certificate status.
		 * 
		 * Response status is the status of OCSP communication (successful, failed, etc.).
		 * 
		 * Certificate status is only available if OCSP communication succeeded (see above)
		 * and shows if the certificate was revoked.
		 * 
		 * See also: http://tools.ietf.org/html/rfc2560#section-4.2.1
		 */

		BasicOCSPResp ocspBasicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
		SingleResp ocspSignleResponse = ocspBasicResponse.getResponses()[0];
		System.out.println("Certificate: " + ocspSignleResponse.getCertID().getSerialNumber());
		if (ocspSignleResponse.getCertStatus() == null) {
			System.out.println("OCSP check passed");
		} else {
			System.out.println("OCSP check failed, status: " + ocspSignleResponse.getCertStatus());
		}
	}
}
