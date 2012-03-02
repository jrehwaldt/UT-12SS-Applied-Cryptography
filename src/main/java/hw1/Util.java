package hw1;

import java.io.FileInputStream;
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;

/*
 * Some helper methods for your convenience.
 * 
 * No need to change anything here.
 */
final class Util {
	public static String toHexString(byte[] data) {
		return new String(Hex.encode(data));
	}

	public static byte[] readFile(String filePath) throws IOException {
		// This will only work fine with small files!
		FileInputStream in = new FileInputStream(filePath);
		byte[] data = new byte[in.available()];
		in.read(data);
		return data;
	}
}
