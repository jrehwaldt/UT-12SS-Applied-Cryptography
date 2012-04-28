package lab15;

import java.io.FileInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;

import common.Util;

public class CmsDemo {
	public static void main(String[] args) throws IOException {
		
//		a.der: encryptedData (digest with sha + encryption with rsa)
//		b.der: digestedData (sha + original data included)
//		c.der: data
//		d.der: signedData (with certificate)
		
		for (String file: args) {
			System.out.println("File: " + file);
			
			FileInputStream in = new FileInputStream(file);
	
			// Read ASN.1 structure from input stream
			ASN1Primitive asn1 = new ASN1InputStream(in).readObject();
			ContentInfo contentInfo = ContentInfo.getInstance(asn1);
	
			// Find out what content we are dealing with
			System.out.println("Content type: " + contentInfo.getContentType());
	
			// Those will have `content ::= SEQUENCE`:
			//  - contentType = signedData: http://tools.ietf.org/html/rfc5652#section-5
			//  - contentType = envelopedData: http://tools.ietf.org/html/rfc5652#section-6
			//  - contentType = digestedData: http://tools.ietf.org/html/rfc5652#section-7
			//  - contentType = encryptedData: http://tools.ietf.org/html/rfc5652#section-8
			//  - contentType = authenticatedData: http://tools.ietf.org/html/rfc5652#section-9
			//
			// However, this type means that content is raw data:
			//  - contentType = data: http://tools.ietf.org/html/rfc5652#section-4
	
			// Extract and dump the content.
			// Note that this will fail if contentType is 'data'!
			// TODOdone: propose some nice workaround
			ASN1Encodable content = (ASN1Encodable) contentInfo.getContent();
			System.out.println("Content: " + Util.toAsn1String(content.toASN1Primitive().getEncoded()));
			
			if (content instanceof DEROctetString) {
				DEROctetString octet = (DEROctetString) content;
				System.out.println("Octet String: " + Util.toHexString(octet.getOctets()) + "\n");
			}
		}
	}
}
