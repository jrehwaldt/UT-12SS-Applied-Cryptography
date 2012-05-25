package lab21;

/*
 * Task 0.
 * Implement createServerSocket(int) method.
 * Check out `SslClient` code for examples.
 * 
 * Task 1.
 * Modify SSL server code to require client authentication.
 * You may need to generate another keystore for client to use.
 */

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class SslServer {
	private static String userHome = System.getProperty("user.home")
		+ System.getProperty("file.separator");
	
	private static String serverKeystorePath =  userHome + "server.jks";
	private static char[] serverKeystorePassword = "password".toCharArray();

	public static void main(String[] args) throws Exception {
		System.out.println(" * Starting server...");
		SSLServerSocket serverSocket = createServerSocket(ServerConf.SSL_SERVER_PORT);
		System.out.println(" * Done, waiting for clients...");

		// Run server loop (this VERY inefficient -- never do it in production!) 
		while (true) {
			SSLSocket clientSocket = null;
			InputStream in = null;
			OutputStream out = null;

			try {
				clientSocket = (SSLSocket) serverSocket.accept();
				clientSocket.addHandshakeCompletedListener(new MyHandshakeCompletedListener());
				System.out.println(" * New session started, client: " + clientSocket.getInetAddress());

				// Initialize socket streams to read from and write to
				in = clientSocket.getInputStream();
				out = clientSocket.getOutputStream();

				// Receive message from client (inefficient way)
				ByteArrayOutputStream messageBuffer = new ByteArrayOutputStream();
				int ch = 0;
				while ((ch = in.read()) != '\0') {
					messageBuffer.write(ch);
				}
				System.out.println("[client] " + messageBuffer.toString());

				// Reply to client
				String message = "Hello, miserable SSL client.";
				System.out.println("[server] " + message);
				out.write(message.getBytes());
				out.write('\0');
			} catch (Exception e) {
				e.printStackTrace();
			}

			// End connection
			if (out != null) {
				out.close();
			}

			if (in != null) {
				in.close();
			}

			if (clientSocket != null) {
				clientSocket.close();
			}
		}
	}

	/**
	 * Creates server SSL socket.
	 */
	private static SSLServerSocket createServerSocket(int port)
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
		SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
		
		return (SSLServerSocket) socketFactory.createServerSocket(port);
	}
}

/**
 * SSL handshake-completed event listener.
 */
class MyHandshakeCompletedListener implements HandshakeCompletedListener {
	/**
	 * Prints some info about this handshake session.
	 */
	public void handshakeCompleted(HandshakeCompletedEvent event) {
		System.out.println("[client] Protocol: " + event.getSession().getProtocol());
		System.out.println("[server] Cipher suite chosen: " + event.getCipherSuite());
		System.out.println(" * SSL handshake completed successfully");
	}
}
