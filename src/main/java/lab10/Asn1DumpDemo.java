package lab10;

import java.io.FileInputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.util.ASN1Dump;

public class Asn1DumpDemo {
	public static void main(String[] args) throws Exception {
		FileInputStream in = new FileInputStream(args[0]);

		// Read file as DER-encoded ASN.1 object
		ASN1Encodable der = new ASN1InputStream(in).readObject();

		// Print file contents
		System.out.println(ASN1Dump.dumpAsString(der, true));
	}
}
