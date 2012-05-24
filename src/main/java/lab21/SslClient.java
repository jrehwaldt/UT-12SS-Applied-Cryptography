<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!DOCTYPE HTML>><HTML><HEAD>
<META content="text/html; charset=windows-1252" 
http-equiv="Content-Type"></HEAD>
<BODY><PRE>package lab21;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Runs SSL client.
 * 
 * This code is based on lab20.HttpsClient but here lower-level structures are used
 * to access sockets directly.
 */
public class SslClient {
	private static String userHome = System.getProperty("user.home")
			+ System.getProperty("file.separator");

	private static String serverKeystorePath =  userHome + "server.jks";
	private static char[] serverKeystorePassword = "password".toCharArray();



	public static void main(String[] args) throws Exception {
		System.out.println(" * Starting client...");
		SSLSocket socket = createSocket(ServerConf.SSL_SERVER_HOST, ServerConf.SSL_SERVER_PORT);

		// Initialize socket streams to read from and write to
		InputStream in = socket.getInputStream();
		OutputStream out = socket.getOutputStream();

		/*
		 * We don't have to use HTTP, so can invent our own protocol instead with
		 * our own message format.
		 */

		// Send message to server
		String message = "Hello, mighty SSL server!";
		System.out.println("[client] " + message);
		out.write(message.getBytes());
		out.write('\0');

		// Receive message from server (inefficient way, do not use in production)
		ByteArrayOutputStream messageBuffer = new ByteArrayOutputStream();
		int ch = 0;
		while ((ch = in.read()) != '\0') {
			messageBuffer.write(ch);
		}
		System.out.println("[server] " + messageBuffer.toString());

		// End connection
		System.out.println(" * Closing connection...");
		out.close();
		in.close();
		socket.close();

		System.out.println("All done.");
	}

	/**
	 * Creates client SSL socket.
	 */
	private static SSLSocket createSocket(String host, int port)
			throws GeneralSecurityException, IOException {
		// Load server certificate from keystore
		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream(serverKeystorePath), serverKeystorePassword);

		// Initialize trust manager factory -- this will handle trusted certificates
		TrustManagerFactory tmFactory = TrustManagerFactory.getInstance("SunX509");
		tmFactory.init(trustStore);

		// Initialize SSL context and create socket factory
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(null, tmFactory.getTrustManagers(), null);
		SSLSocketFactory socketFactory = sslContext.getSocketFactory();

		return (SSLSocket) socketFactory.createSocket(host, port);
	}
}
</PRE></BODY></HTML>
