package ee.ut.appcrypto.lecture2;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class Hasher {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, DecoderException {
        
        if (args.length < 2) {
            System.out.println("Usage: Hasher <Algorithm> <File> [<Digest>]");
            System.exit(1);
        }
        
        String algorithm = args[0];
        String fileName = args[1];
        
        FileInputStream fis = new FileInputStream(fileName);
        byte[] data = new byte[fis.available()];
        fis.read(data);
        fis.close();
        
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(data);
        
        System.out.println("Digest: " + toHexString(digest));
        
        if (args.length == 3) {
            String digestFileName = args[2];
            
            FileReader digestReader = new FileReader(digestFileName);
            BufferedReader bufferedDigestReader = new BufferedReader(digestReader);
            String hexDigest = bufferedDigestReader.readLine();
            
            bufferedDigestReader.close();
            digestReader.close();
            
            byte[] digestData = fromHexString(hexDigest);
            
            if (Arrays.equals(digestData, digest)) {
                System.out.println("Digest matches");
            } else {
                System.out.println("Digest does not match");
            }
        }
    }
    
    private static String toHexString(byte[] data) {
        return String.valueOf(Hex.encodeHex(data));
    }
    
    private static byte[] fromHexString(String hex) throws DecoderException {
        return Hex.decodeHex(hex.toCharArray());
    }
}
