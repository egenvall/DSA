package com.company;

import java.math.BigInteger;

/**
 * Kim Egenvall
 */
public class DSASignature {
    private BigInteger r;
    private BigInteger s;

    public DSASignature(){

    }

    public DSASignature(BigInteger s, BigInteger r){
        this.s = s;
        this.r = r;
    }

    public BigInteger getS(){
        return this.s;
    }

    public BigInteger getR(){
        return this.r;
    }
    public void setS(BigInteger s){
        this.s = s;
    }
    public void setR(BigInteger r){
        this.r  = r;
    }
}
