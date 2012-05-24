package lab20;

/*
 * Task 2: Fix and get HTTPS client running.
 * 
 * Make sure you get HTML downloaded and printed to stdout.
 * 
 * Check out comments below.
 */

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Runs a simple HTTPS client that connect to HTTPS server (see `HttpsServer` class).
 * 
 * For this code to run, you will need a server certificate in a keystore.
 * 
 * Ideally, you will have to create a keystore containing all trusted certificates
 * you would like to use in server certificate verification.
 * 
 * For this task, use the same keystore you created for `HttpsServer`.
 * 
 * If using some other keystore, update `serverKeystorePath` and
 * `serverKeystorePassword` variables below as needed.
 */
public class HttpsClient {
	
	private static String userHome = System.getProperty("user.home")
			+ System.getProperty("file.separator");

	private static String keystorePath =  userHome + "server.jks";
	private static String keystorePassword = "password";
	
	public static void main(String[] args) throws Exception {
		/*
		 * You will need to create an instance of class SSLContext.
		 * This will be used to store SSL/TLS connection parameters
		 * and create SSL sockets for connection -- see code below.
		 * 
		 * To create SSLContext, you will need to provide key manager, trust manager
		 * and randomness generator. Check the javadoc for SSLContext to see
		 * what values can these parameters have.
		 * 
		 * Key manager will store client authentication keys -- 'our info'.
		 * It is only needed if client authentication is required by server.
		 * 
		 * Trust manager will store trusted server certificates -- 'their info'.
		 * It is only needed if server certificate is not trusted by default.
		 * 
		 * Hints:
		 *  - KeyStore type should be "JKS"
		 *  - TrustManagerFactory algorithm should be "SunX509"
		 *  - SSLContext protocol should be "TLS"
		 * 
		 */
		SSLContext sslContext = SSLContext.getInstance("SSLv3"); // FIXME
        System.out.println("\nSSLContext class: " + sslContext.getClass());
        System.out.println("   Protocol: " + sslContext.getProtocol());
        System.out.println("   Provider: " + sslContext.getProvider());
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
	    System.out.println("\nKeyManagerFactory class: " + kmf.getClass());
	    System.out.println("   Algorithm: " + kmf.getAlgorithm());
	    System.out.println("   Provider: " + kmf.getProvider());
	    
     	 // KeyStore types: JKS
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
        System.out.println("\nKeyStore class: " + ks.getClass());
        System.out.println("   Type: " + ks.getType());
        System.out.println("   Provider: " + ks.getProvider());
        System.out.println("   Size: " + ks.size());
        
        // Generating KeyManager list
        kmf.init(ks, keystorePassword.toCharArray());
        System.out.println("\nKeyManager class: " + kmf.getKeyManagers().getClass());
        System.out.println("   # of key manager: " + kmf.getKeyManagers().length);
	    

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
	    System.out.println("\nTrustManagerFactory class: " + tmf.getClass());
	    System.out.println("   Algorithm: " + tmf.getAlgorithm());
	    System.out.println("   Provider: " + tmf.getProvider());
	    
	    tmf.init(ks);
        
		SecureRandom rand = new SecureRandom();
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), rand);

		// Initialize HTTPS connection
		URL url = new URL(
				"https://" + ServerConf.HTTPS_SERVER_HOST + ":" + ServerConf.HTTPS_SERVER_PORT);
		HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
		connection.setSSLSocketFactory(sslContext.getSocketFactory());
		connection.connect();

		// Receive message from server (inefficient, do not use in production)
		InputStream in = connection.getInputStream();
		ByteArrayOutputStream messageBuffer = new ByteArrayOutputStream();
		int ch = 0;
		while ((ch = in.read()) >= 0) {
			messageBuffer.write(ch);
		}
		System.out.println(messageBuffer.toString());
	}
}
