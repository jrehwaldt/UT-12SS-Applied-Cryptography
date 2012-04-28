package lab12;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import common.Util;


/*
 * You will need both BouncyCastle provider and TSP libraries for this task,
 * get those here: http://www.bouncycastle.org/latest_releases.html
 * (you need Provider and PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL packages).
 * 
 * BouncyCastle TSP documentation:
 * http://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/tsp/package-summary.html
 * 
 * You can use common.Util.toHexString() and common.Util.toAsn1String()
 * to print some encoded values.
 */
public class TspDemo {
	// Some TSAs to test
	//private static String tsaUrl = "http://tsa.aloaha.com/";
	private static String tsaUrl = "http://timestamping.edelweb.fr/service/tsp";



	public static void main(String[] args) throws Exception {
		byte[] data = "MyData".getBytes();

		// Compute data hash
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] dataHash = digest.digest(data); // FIXME

		// Prepare timestamp request.
		//
		// You may want to use TimeStampRequestGenerator class.
		//
		// See also:
		//   - http://tools.ietf.org/html/rfc3161#section-2.4.1
		
		TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
		TimeStampRequest request = requestGenerator.generate(NISTObjectIdentifiers.id_sha256, dataHash); // FIXME

		// Prepare connection to TSA
		HttpURLConnection connection = (HttpURLConnection) new URL(tsaUrl).openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Content-Type", "application/timestamp-request");
		connection.setDoOutput(true);
		connection.connect();

		// Send timestamp request
		OutputStream out = connection.getOutputStream();
		out.write(request.getEncoded());
		out.flush();

		// Receive timestamp response.
		//
		// See also:
		//   - http://tools.ietf.org/html/rfc3161#section-2.4.2
		InputStream in = connection.getInputStream();
		TimeStampResponse response = new TimeStampResponse(in);
		
		// TODO: Print response status. What does it mean?
		//   PKIStatus ::= INTEGER {
		//	      granted                (0),
		//	      -- when the PKIStatus contains the value zero a TimeStampToken, as
		//	         requested, is present.
		//	      grantedWithMods        (1),
		//	       -- when the PKIStatus contains the value one a TimeStampToken,
		//	         with modifications, is present.
		//	      rejection              (2),
		//	      waiting                (3),
		//	      revocationWarning      (4),
		//	       -- this message contains a warning that a revocation is
		//	       -- imminent
		//	      revocationNotification (5)
		//	       -- notification that a revocation has occurred  }
		System.out.println("Response Status: " + connection.getResponseCode() + " [" + connection.getResponseMessage() + "]");
		System.out.println("Status: " + response.getStatus());
		
		if (response.getStatus() > 0) {
			throw new IllegalArgumentException("Something really bad!");
		}
		
		// TODO: Extract timestamp (token) and timestamp info from timestamp response
		//
		// From http://tools.ietf.org/html/rfc3161#section-2.4.2:
		//
		// TimeStampResp {
		//     -- Some fields skipped
		//     TimeStampToken {
		//         -- Some fields skipped
		//         TSTInfo { -- Timestamp Token Info
		//             -- Fields you need
		//         }
		//     }
		// }
		
		TimeStampToken token = response.getTimeStampToken();
		TimeStampTokenInfo info = token.getTimeStampInfo();

		// Print some timestamp fields -- replace nulls with actual values
		System.out.println("Digest Algorithm OID: " + info.getMessageImprintAlgOID());
		System.out.println("Message Digest: " + Util.toHexString(info.getMessageImprintDigest()));
		System.out.println("Time: " + info.getGenTime());
		System.out.println("TSA: " + info.getTsa());

		// Simple timestamp verification
		if (Arrays.equals(dataHash, info.getMessageImprintDigest())) { // TODO: compare initial digest with one from timestamp info
			System.out.println("GREAT SUCCESS");
		} else {
			System.out.println("GLORIOUS FAIL");
		}
		// Note that this verification process is not complete.
		// You will also have to check signatures, extensions, times, etc.
		// We will talk about correct verification process later.
	}
}
