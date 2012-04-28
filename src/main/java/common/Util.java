package common;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.encoders.Hex;

public final class Util {
	public static void download(URL url, String filePath) throws IOException {
		ReadableByteChannel rbc = Channels.newChannel(url.openStream());
		FileOutputStream out = new FileOutputStream(filePath);
		out.getChannel().transferFrom(rbc, 0, 16777216);
	}

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

	public static byte[] sha256(byte[] digest1, byte[] digest2) {
		try {
			byte[] data = new byte[64];
			System.arraycopy(digest1, 0, data, 0, 32);
			System.arraycopy(digest2, 0, data, 32, 32);
			return MessageDigest.getInstance("SHA-256").digest(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return "00000000000000000000000000000000".getBytes();
	}
}
