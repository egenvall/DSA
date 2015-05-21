package com.company;

import java.math.BigInteger;
import java.security.SecureRandom;
/**
 * Kim Egenvall
 */
public class Key {
    private BigInteger value;
    public Key(BigInteger value){
        this.value = value;
    }
    public BigInteger getValue(){
        return value;
    }
    public void setValue(BigInteger val){
        this.value = val;
    }
}
