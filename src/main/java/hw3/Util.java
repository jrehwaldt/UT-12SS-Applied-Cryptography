package hw3;

import java.io.FileInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.encoders.Hex;

/*
 * You do not have to change anything here.
 */

public final class Util {
	public static byte[] readFile(String filePath) throws IOException {
		// This will only work fine with small files!
		FileInputStream in = new FileInputStream(filePath);
		byte[] data = new byte[in.available()];
		in.read(data);
		return data;
	}

	public static String toAsn1String(byte[] data) {
		try {
			return ASN1Dump.dumpAsString(ASN1Sequence.fromByteArray(data));
		} catch (IOException e) {
			throw new IllegalArgumentException("Invalid input, details: " + e.getMessage());
		}
	}

	public static String toHexString(byte[] data) {
		return new String(Hex.encode(data));
	}

	public static byte[] fromHexString(String str) {
		return Hex.decode(str);
	}
}
