package ee.ut.appcrypto.lecture2;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Encrypt {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        
        if (args.length < 3) {
            System.out.println("Usage: Encrypt <File> <Enc> <Pass>");
            System.exit(1);
        }
        
        String fileName = args[0];
        String algorithm = args[1];
        String pass = args[2];
        
        FileInputStream fis = new FileInputStream(fileName);
        byte[] data = new byte[fis.available()];
        fis.read(data);
        fis.close();
        
        byte[] keyData = pass.getBytes();
        
        //
        // http://stackoverflow.com/questions/1205135/how-to-encrypt-string-in-java
        //
        
        SecretKeySpec key = new SecretKeySpec(keyData, "DES");
        
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.update(data);
        
        System.out.println("Encrypted: " + Arrays.toString(encrypted));
    }
}
