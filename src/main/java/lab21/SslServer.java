<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!DOCTYPE HTML>><HTML><HEAD>
<META content="text/html; charset=windows-1252" 
http-equiv="Content-Type"></HEAD>
<BODY><PRE>package lab21;

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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

public class SslServer {
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
		return null; // FIXME
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
</PRE></BODY></HTML>
