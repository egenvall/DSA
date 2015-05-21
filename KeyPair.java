package com.company;

import java.math.BigInteger;
/**
 * Kim Egenvall
 * Class for holding two Keys, a private key X and a public  key Y
 */
public class KeyPair {
    BigInteger x;
    BigInteger y;

    public KeyPair(BigInteger x, BigInteger y){
        this.x = x;
        this.y = y;
    }

    public BigInteger getX(){
        return x;
    }
    public BigInteger getY(){
        return y;
    }
}
