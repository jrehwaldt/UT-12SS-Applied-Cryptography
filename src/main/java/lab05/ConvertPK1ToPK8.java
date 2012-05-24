package lab05;

import java.io.FileInputStream;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


public class ConvertPK1ToPK8 {

  public static void main(String[] args) throws Exception {
    InputStream in = new FileInputStream(args[0] + "priv.der");
    ASN1Encodable der = new ASN1InputStream(in).readObject();
    System.out.println("DER: " + ASN1Dump.dumpAsString(der));
    
    DERSequence sequence = (DERSequence) der;
    if (sequence.size() != 9) {
    	System.exit(-1);
    }
    
//    PrivateKeyInfo ::= SEQUENCE {
//        version                   Version,
//        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
//        privateKey                PrivateKey,
//        attributes           [0]  IMPLICIT Attributes OPTIONAL }
//
//      Version ::= INTEGER
//
//      PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//
//      PrivateKey ::= OCTET STRING
//
//      Attributes ::= SET OF Attribute
    
//    DER Sequence
//        Integer(0)
//        DER Sequence
//            ObjectIdentifier(1.2.840.113549.1.1.1)
//            NULL
//        DER Octet String[1192] 
    ASN1Encodable version = sequence.getObjectAt(0);
    ASN1Encodable privateKey = new AlgorithmIdentifier(new DERObjectIdentifier("1.2.840.113549.1.1.1"));
    ASN1Encodable attributes = new DEROctetString(der);
    
    ASN1EncodableVector pk8 = new ASN1EncodableVector();
    pk8.add(version);
    pk8.add(privateKey);
    pk8.add(attributes);
    
    DERSequence pk8Result = new DERSequence(pk8);
    System.out.println("DER Sequence"
    		+ "\n    Integer(0)"
    		+ "\n    DER Sequence"
    		+ "\n        ObjectIdentifier(1.2.840.113549.1.1.1)"
    		+ "\n        NULL"
    		+ "\n    DER Octet String[1192]");
    System.out.println("RESULT: " + ASN1Dump.dumpAsString(pk8Result));
  }
}
