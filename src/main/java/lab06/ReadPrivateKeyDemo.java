package lab06;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import common.Util;

/*
 * Demonstrates how to read PKCS#8-encoded private key from file and
 * print the private key contents.
 * 
 * Note that PKCS#8 is not the format OpenSSL is using, you'll have to
 * convert keys generated by OpenSSL.
 * 
 * See also:
 *   http://en.wikipedia.org/wiki/PKCS
 *   http://www.openssl.org/docs/apps/pkcs8.html 
 */
public class ReadPrivateKeyDemo {
	public static void main(String[] args) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		byte[] encodedKey = Util.readFile(args[0]);

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		System.out.println(privateKey);
	}
}
