package lab20;

/*
 * Task 1: Get HTTPS server running.
 * 
 * Check out the comments below.
 * 
 * Start the server and open https://localhost:8443/ in your browser.
 * Bypass the self-signed certificate warning, if needed.
 * Make sure you get the HTML page displayed.
 * 
 * Once running, you can stop the server by pressing Ctrl+C in console or
 * 'Terminate' in Eclipse.
 */

import java.io.IOException;
import java.io.OutputStream;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * Runs a simple HTTPS server on (see `ServerConf` class for details on host and port).
 * 
 * For this code to run, you will need server SSL certificate. Here Java keystore
 * is used to store server certificates, you'll need to generate one first.
 * Keystore with one self-signed certificate is enough. Example for Linux:
 * 
 *     keytool -genkey -keyalg RSA -dname "CN=localhost" -keystore ~/server.jks
 * 
 * ... or if you have a keystore already or want to use another path,
 * fix `serverKeystorePath` variable accordingly.
 * 
 * Set the keystore password to 'password' or fix the `serverKeystorePassword`
 * variable as needed.
 * 
 * Note:
 * HTTPS connection to this server may fail in Chrome/Chromium because of their
 * specific SSL implementation. Use Firefox for this example.
 */
public class HttpsServer {
	private static String userHome = System.getProperty("user.home")
			+ System.getProperty("file.separator");

	private static String serverKeystorePath =  userHome + "server.jks";
	private static String serverKeystorePassword = "password";



	/**
	 * Runs HTTPS server.
	 */
	public static void main(String[] args) throws Exception {
		System.out.println(" * Starting server...");
		SSLServerSocket serverSocket = createServerSocket(ServerConf.HTTPS_SERVER_PORT);
		System.out.println(" * Done, waiting for clients...");

		// Run server loop (inefficient, do not use in production)
		while (true) {
			OutputStream out = null;
			SSLSocket clientSocket = null;

			try {
				// Accept client connection
				clientSocket = (SSLSocket) serverSocket.accept();
				System.out.println(" * Client connected: " + clientSocket.getInetAddress());

				// Initialize client socket stream to write to
				out = clientSocket.getOutputStream();

				// Reply to client -- send headers
				out.write("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n".getBytes());

				// Send page contents
				out.write("<html><body>Tere hommikust Aleksandra! :)</body></html>".getBytes());
			} catch (Exception e) {
				System.out.println(e.getMessage());
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
	 * Initializes server socket connection.
	 */
	private static SSLServerSocket createServerSocket(int port) throws IOException {
		if (System.getProperty("javax.net.ssl.keyStore") == null) {
			// Set your keystore path and password
			System.setProperty("javax.net.ssl.keyStore", serverKeystorePath);
			System.setProperty("javax.net.ssl.keyStorePassword", serverKeystorePassword);
		}

		SSLServerSocketFactory socketFactory =
				(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		return (SSLServerSocket) socketFactory.createServerSocket(port);
	}
}
