package lab01;

import java.math.BigInteger;

public class PowerOfBigInteger {

    /**
     * @param args
     */
    public static void main(String[] args) {
        BigInteger a = BigInteger.valueOf(Long.MAX_VALUE);
        System.out.println(a.pow(2).mod(BigInteger.valueOf(10000)));
    }

}
