package lab14;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/*
 * Timestamping client demo that talks to TSA server using socket connections.
 * 
 * Slightly modified version of demo code from Lab 12, this time using socket
 * connections instead of HTTP. All the transport logic is implemented for you.
 * 
 * As a result of running this code (once fixed), you should receive a valid
 * RFC 3161 timestamp. Make sure you verify it at once.
 * 
 * @see lab14.TsaServerDemo
 */
public class TsaClientDemo {
	// FIXME: use http://www.oid-info.com/ to find SHA256 object identifier
	private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";
	// FIXME: server address will be announced in class.
	// If you decide to run server locally (see TsaServerDemo), 'localhost' should work.
	private static final String SERVER_HOST = "172.17.36.85";
	private static final int SERVER_PORT = 3333;

	public static void main(String[] args) throws Exception {
		// FIXME: use some hard-coded string or read data from file
		byte[] data = "We're the champions".getBytes();

		// Compute data hash
		byte[] dataHash = MessageDigest.getInstance("SHA-256").digest(data);

		// Prepare timestamp request
		TimeStampRequest request = new TimeStampRequestGenerator().generate(
				new ASN1ObjectIdentifier(SHA256_OID), dataHash);

		// Init TSA connection
		Socket socket = new Socket(SERVER_HOST, SERVER_PORT);

		// Send timestamp request
		System.out.println(" * Sending timestamp request...");
		OutputStream out = socket.getOutputStream();
		out.write(request.getEncoded());
		out.flush();

		// Receive timestamp response
		InputStream in = new BufferedInputStream(socket.getInputStream());
		TimeStampResponse response = new TimeStampResponse(in);

		// FIXME: make sure to check timestamp response status.
		// See also: http://tools.ietf.org/html/rfc3161#section-2.4.2
		response.validate(request);

		// End connection
		out.close();
		in.close();
		socket.close();

		// FIXME: check data digest in timestamp. Does it match the one you've sent?
		TimeStampTokenInfo info = response.getTimeStampToken().getTimeStampInfo();
		System.out.println("Match: " + Arrays.equals(dataHash, info.getMessageImprintDigest()));
		
		// FIXME: print serial number from the timestamp you've got.
		// You will need this number later. No need to write it down separately,
		// you can always extract it from timestamp.
		System.out.println("Serial: " + info.getSerialNumber());

		// FIXME: verify the timestamp signature.
		// It is okay to use deprecated method
		// `TimeStampToken.validate(X509Certificate, String)` here.
		Security.addProvider(new BouncyCastleProvider());
		
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		
		FileInputStream certFis = new FileInputStream("src/lab14/tsa.crt");
		X509Certificate cert = (X509Certificate) factory.generateCertificate(certFis);
		certFis.close();
		response.getTimeStampToken().validate(cert, "BC");

		// FIXME: store timestamp to file.
		// Make sure you can read the timestamp from that file later.
		FileOutputStream fis = new FileOutputStream("timestamp.ts");
		fis.write(response.getEncoded());
		fis.close();
	}
}
