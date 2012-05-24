package lab04;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyStoreMain {

    /**
     * What signature algorithm is used? 
     * What is certificate validity period? 
     * How can you change those? 
     */
    public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        
    	char[] password = "secrete".toCharArray();
    	
        //
        // 1. Access generated keystore from Java code (certificate, private key) 
        // 2. Inspect extracted private key and certificate 
        //
        
        FileInputStream fis = new FileInputStream("src/main/resources/utdemo.jks");
        
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        
        store.load(fis, password);
        fis.close();
        
        X509Certificate cert = (X509Certificate) store.getCertificate("UtDemoKey");
        System.out.println(cert);
        
        // What signature algorithm is used?:    SHA1withRSA
        // What is certificate validity period?: 3 month
        // How can you change those?:            via keytool api
        
        //
        // 1. Add another certificate to the same keystore, valid for 2 years
        //    and using some other than default signature algorithm.
        //
        Security.addProvider(new BouncyCastleProvider());
        
//        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) store.getEntry("UtDemoKey", password);
//        PrivateKey myPrivateKey = pkEntry.getPrivateKey();
        
//        // save my secret key
//        javax.crypto.SecretKey mySecretKey = MyKeyGenerator.generateAesSecretKey(password);
//        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
//        store.setEntry("UtDemoKey2", skEntry, new KeyStore.PasswordProtection(password));
//        
//        // store away the keystore
//        java.io.FileOutputStream fos = null;
//        try {
//            fos = new java.io.FileOutputStream("utdemo-with-2.jks");
//            store.store(fos, password);
//        } finally {
//            if (fos != null) {
//                fos.close();
//            }
//        }

    }

}
