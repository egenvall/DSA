package com.company;

import java.math.BigInteger;

/**
 * Kim Egenvall
 */
public class User {
    public static final int L = 1024;
    public static final int N = 160;

    /*See fips_186-3.pdf Ch 4.3 Domain Parameters*/
    private BigInteger[] domainParameters = new BigInteger[3];
    private Key publicKey;
    private Key privateKey;

    public boolean checkInput(BigInteger p, BigInteger q, BigInteger g) {
        /* Check that length of input bits matches the DSA Standard option : L - 1024 N 160*/
        if (g.compareTo(BigInteger.ONE) <= 0 || p.bitLength() != L || q.bitLength() != N) {
            return false;
        }

        /*Check that q divides p-1  eg p-1 mod q = 0
        * x.compareTo(y) returns : -1 if x is less, 0 if equal, or 1 if x is bigger than y*/
        BigInteger pSubtractedByOne = p.subtract(BigInteger.ONE);
        if (pSubtractedByOne.remainder(q).compareTo(BigInteger.ZERO) != 0) {
            return false;
        }

        /*Check that g^q mod p = 1 and g > 1*/
        if (g.modPow(q, p).compareTo(BigInteger.ONE) != 0) {
            return false;
        }

        /*Verify that p and q are prime numbers*/
        int certain = 20;
        if (!p.isProbablePrime(certain)) {
            return false;
        }
        if (!q.isProbablePrime(certain)) {
            return false;
        }

        /*Input was valid, return true*/
        return true;
    }

    public User(BigInteger p, BigInteger q, BigInteger g) throws Exception {
        if(checkInput(p,q,g)) {
            this.domainParameters[0] = p;
            this.domainParameters[1] = q;
            this.domainParameters[2] = g;
        }
        else{
            throw new Exception();
        }
    }

    public User(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y)throws Exception {
        if(checkInput(p,q,g)) {
            this.domainParameters[0] = p;
            this.domainParameters[1] = q;
            this.domainParameters[2] = g;
            this.privateKey.setValue(x);
            this.publicKey.setValue(y);
        }
        else{
            throw new Exception();
        }
    }

    public BigInteger getP() {
        return this.domainParameters[0];
    }
    public BigInteger getQ() {
        return this.domainParameters[1];
    }
    public BigInteger getG() {
        return this.domainParameters[2];
    }
    public BigInteger getX(){
        return this.privateKey.getValue();
    }

    public BigInteger getY(){
        return this.publicKey.getValue();
    }

    public void setX(Key x){
        this.privateKey = x;
    }
    public void setY(Key y){
        this.publicKey = y;
    }
}