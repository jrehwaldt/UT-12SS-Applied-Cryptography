package ee.ut.appcrypto.lecture1;

import java.math.BigInteger;
import java.util.Random;

public class PlaintextCipher {

    /**
     * @param args
     */
    public static void main(String[] args) {
        
        String text = "save seen to see the Galaxy also had gone! Nelson's Column only thing is the distance of shaking space and Everything? To tremendous before Yooden but also his head, the fabric of He was now complained Arthur, hopelessly. - Is... - you feel understood In orbit finger I of a simple truth in advance. The word yellow thing is so keen to like the history lost. - clearly not knowing what else to like useful spent those fifteen years said Ford.";
        BigInteger num = new BigInteger(text.getBytes());
        
        Random rand = new Random();
        BigInteger key = new BigInteger(num.bitLength(), rand);
        
        BigInteger cipher = num.xor(key);
        BigInteger restored = cipher.xor(key);
        
        System.out.println(String.format(
                "Text:\t\t%s\nKey:\t\t%d\nCipher:\t\t%d\nNumerical:\t%s\nRestored:\t%d\nMatch:\t\t%s\n",
                text,
                key,
                cipher,
                num,
                restored,
                "How to get it?",
                num.equals(restored)));
    }
}
