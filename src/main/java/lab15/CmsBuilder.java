package lab15;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEncryptedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

// http://tools.ietf.org/html/rfc5652
// http://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/cms/jcajce/package-summary.html
public class CmsBuilder {
	public static void main(String[] args) throws Exception {
		byte[] data = "All your base are belong to us".getBytes();

		Security.addProvider(new BouncyCastleProvider());

		write(buildEncryptedData(data), "a.der");
		write(buildDigestedData(data), "b.der");
		write(buildData(data), "c.der");
		write(buildSignedData(data), "d.der");
	}

	private static ContentInfo buildData(byte[] data) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1")); // data
		v.add(new DERTaggedObject(true, 0, new DEROctetString(data)));

		return new ContentInfo(new DERSequence(v));
	}

	private static ContentInfo buildDigestedData(byte[] data) throws GeneralSecurityException {
		ASN1EncodableVector v;

		byte[] digest = MessageDigest.getInstance("SHA256").digest(data);

		// Build encapsulated content info
		// contentType = data: http://tools.ietf.org/html/rfc5652#section-4
		v = new ASN1EncodableVector();
		v.add(new ASN1ObjectIdentifier("1.2.840.113549.1.7.1"));
		v.add(new DERTaggedObject(true, 0, new DEROctetString(data)));
		ContentInfo encapContentInfo = new ContentInfo(new DERSequence(v));

		// Build content
		v = new ASN1EncodableVector();
		v.add(new DERInteger(0)); // http://tools.ietf.org/html/rfc5652#section-7
		v.add(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
		v.add(encapContentInfo);
		v.add(new DEROctetString(digest));
		DERSequence content = new DERSequence(v);

		// Build outer content info
		v = new ASN1EncodableVector();
		v.add(new ASN1ObjectIdentifier("1.2.840.113549.1.7.5")); // digestedData
		v.add(new DERTaggedObject(true, 0, content));

		return new ContentInfo(new DERSequence(v));
	}

	// See http://tools.ietf.org/html/rfc5652#section-8
	private static ContentInfo buildEncryptedData(byte[] data)
			throws CMSException {
		CMSTypedData typedData = new CMSProcessableByteArray(data);

		OutputEncryptor encryptor =
				new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).build();

		CMSEncryptedDataGenerator generator = new CMSEncryptedDataGenerator();

		return generator.generate(typedData, encryptor).toASN1Structure();
	}

	// See http://tools.ietf.org/html/rfc5652#section-5
	//
	// You will need private key and public key certificate for this to work.
	// Self-signed certificate is okay here.
	// Lab 6 has examples on how to generate those.
	private static ContentInfo buildSignedData(byte[] data)
			throws CMSException, GeneralSecurityException, IOException, OperatorCreationException {
		CMSTypedData typedData = new CMSProcessableByteArray(data);

		// This will generate final SignedData structure
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

		// This will generate SignerInfo structures -- should be done for every signer
		PEMReader certificateReader = new PEMReader(new FileReader("tsa.crt"));
		X509Certificate certificate = (X509Certificate) certificateReader.readObject();

		PEMReader keyReader = new PEMReader(new FileReader("tsa.priv"));
		PrivateKey signingKey = ((KeyPair) keyReader.readObject()).getPrivate();

		DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();

		ContentSigner contentSigner =
				new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);

		SignerInfoGenerator signerInfoGenerator =
				new JcaSignerInfoGeneratorBuilder(digestProvider).build(contentSigner, certificate);
		generator.addSignerInfoGenerator(signerInfoGenerator);

		return generator.generate(typedData).toASN1Structure();
	}

	private static void write(ContentInfo contentInfo, String filePath) throws IOException {
		FileOutputStream out = new FileOutputStream(filePath);
		out.write(contentInfo.getEncoded());
		out.flush();
		out.close();
	}
}
