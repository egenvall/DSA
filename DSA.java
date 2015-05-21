package com.company;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

/**
 * Kim Egenvall
 */
public class DSA {
    private User user;


    public DSA(BigInteger p, BigInteger q, BigInteger g)throws Exception{
        this.user = new User(p,q,g);
    }

    public DSA(BigInteger p, BigInteger q, BigInteger g,BigInteger x, BigInteger y)throws Exception{
        this.user = new User(p,q,g,x,y);
    }

    /**
     * Generate n number of keys specified by input
     * @param n
     * @return
     */
    public ArrayList<KeyPair> generateKeyPair(BigInteger n){
        ArrayList<KeyPair> keylist = new ArrayList<KeyPair>();
        for(int i = 0; i < n.intValue();i++){
            Key x = new Key(generateX());
            /*y = g^x mod p*/
            Key y = new Key(user.getG().modPow(x.getValue(),user.getP()));

            /* KeyPair with keys x,y*/
            KeyPair pair = new KeyPair(x.getValue(),y.getValue());
            keylist.add(i,pair);
        }
        return keylist;
    }
    /* Generate private key x in the interval 0<x<q*/
    public BigInteger generateX(){
        System.out.println("Entering generateX");
        SecureRandom random = new SecureRandom();
        System.out.println("After random gen");
        BigInteger x;
        do{
            /*Generate a random number of max bit length = q's bitlength to satisfy x<q*/
            x = new BigInteger(getQ().bitLength(),random);
        }
        //Make sure that the number x is chosen randomly in the interval 0 < x <  q
        while((getQ().compareTo(x) < 1) || (x.compareTo(BigInteger.ZERO) < 1));
        return x;
    }
    /**Generate a cryptographically secure random k 0<k<q
     *
     * @return random k
     */
    public BigInteger generateK(){
        System.out.println("Entering generateK");
        SecureRandom random = new SecureRandom();
        System.out.println("Random number generated");
        BigInteger k;
        System.out.println("entering do in generateK");
        do{
            /*Generate a random number of max bit length = q's bitlength to satisfy k<q*/
            k = new BigInteger(getQ().bitLength(),random);
        }
        /*Make sure 0<k<q*/
        while ((getQ().compareTo(k) < 1) || (k.compareTo(BigInteger.ZERO) < 1));
        return k;
    }

    /** Method takes a string of 40hexadecimal digits, converts it to decimal
     * and returns a signature.
     *
     * @param digestMessage
     * @return DSASignature
     */
    public DSASignature sign(String digestMessage){
        if(digestMessage.length() != 40){
            throw new IllegalArgumentException("Hash is not of correct length");
        }
        else{
            /*Parse hex string to integer*/
            BigInteger z = new BigInteger(digestMessage,16) ;
            BigInteger k = generateX();
            System.out.println("returning from generateK");
            /*r = (g^k mod p)mod q*/
            BigInteger r = getG().modPow(k,getP()).mod(getQ());

            /* s = (k^-1(z+xr) mod q*/
            BigInteger s = (k.modInverse(getQ()).multiply(z.add(getX().multiply(r)))).mod(getQ());
            System.out.println("Leaving sign");
            return new DSASignature(s,r);
        }
    }

    /** Verification following the steps of Ch 4.7
     * in fips_186-3.pdf Digital Signature Standard
     *
     * @param user
     * @param digestMessage
     * @param sign
     * @return
     */
    public boolean verify(User user,String digestMessage,DSASignature sign){
        BigInteger publicKey = user.getY();
        BigInteger sRecieved = sign.getS();
        BigInteger rRecieved = sign.getR();

        /* Check that 0< r < q  && 0 < s < q, if not deny the verification */
        if(((rRecieved.compareTo(getQ()) >= 0 ||rRecieved.compareTo(BigInteger.ZERO) <= 0))
            && (sRecieved.compareTo(getQ()) >= 0 || sRecieved.compareTo(BigInteger.ZERO) <= 0)){
            return false;
        }

        /*Parse hex string to integer */
        BigInteger z = new BigInteger(digestMessage,16);
        /* w = sRecieved^-1 mod q */
        BigInteger w = sRecieved.modInverse(getQ());
        /* u1 = (zw) moq q */
        BigInteger u1 = (z.multiply(w)).mod(getQ());
        /*u2 = ((rRecieved)w) mod q */
        BigInteger u2 = (rRecieved.multiply(w)).mod(getQ());
        /* v = (((g)^u1 * (publicKey)^u2) mod p) mod q*/
        BigInteger v = ((getG().modPow(u1,getP()).multiply(publicKey.modPow(u2,getP()))).mod(getP())).mod(getQ());

        /*if v == rRecieved the verification is successful*/
        return v.compareTo(rRecieved) == 0;
    }





    public BigInteger getQ(){
        return user.getQ();
    }
    public BigInteger getP(){
        return user.getP();
    }
    public BigInteger getG(){
        return user.getG();
    }
    public BigInteger getX(){
        return user.getX();
    }
    public BigInteger getY(){
        return user.getY();
    }
    public User getUser(){
        return this.user;
    }
    public void setX(BigInteger x){
        user.setX(new Key(x));
    }
    public void setY(BigInteger y){
        user.setY(new Key(y));
    }

}
