package com.company;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * Kim Egenvall
 */
public class Start {
    public static void checkOnlyNumerals(String s)throws Exception{
        if(!s.matches("[0-9]+")) {
            throw new Exception();
        }

    }

    public static void isAlphaNumeric(String s){
        if(!s.matches("^[a-zA-Z0-9]*$")){
            throw new IllegalArgumentException();
        }
    }

    public static void main(String[] args) throws Exception {
	BufferedReader input = null;
        try{
            input = new BufferedReader(new InputStreamReader(System.in));
            String line;
            String[] domainParameters = new String[3];
            domainParameters[0] = input.readLine().split("^p=")[1];
            domainParameters[1] = input.readLine().split("^q=")[1];
            domainParameters[2] = input.readLine().split("^g=")[1];

            /*System.out.println("p=" + domainParameters[0]);
            System.out.println("q=" + domainParameters[1]);
            System.out.println("g=" + domainParameters[2]);*/

            /*Verify that parameters only consists of numeric values*/
            for(String domainParameter : domainParameters){
                checkOnlyNumerals(domainParameter);
            }

            /*Create a DSA with the domain paremeters. Upon creation the user class validates the parameters,
            * if they are not correct an exception will be thrown*/
            DSA dsa = new DSA(new BigInteger(domainParameters[0]),new BigInteger(domainParameters[1]),new BigInteger(domainParameters[2]));


            line = input.readLine();
            /*Check which statement comes next: genkey, sign, or verify*/
            if(line.equals("genkey")){
                String s = (input.readLine().split("n="))[1];
                /*Check that it is a number*/
                checkOnlyNumerals(s);
                System.out.println("valid group");
                ArrayList<KeyPair> keys = dsa.generateKeyPair(new BigInteger(s));
                for(KeyPair k : keys){
                    System.out.println("x="+k.getX());
                    System.out.println("y="+k.getY());
                }
            }
            else if(line.equals("sign")){
                String x = (input.readLine().split("x="))[1];
                String y = (input.readLine().split("y="))[1];
                checkOnlyNumerals(x);
                checkOnlyNumerals(y);

                ArrayList<String> digest = new ArrayList<String>();
                boolean endOfFil = false;
                while (!endOfFil) {
                    line = input.readLine();
                    if (line != null) {
                        System.out.println("Adding line to list");
                        digest.add(line.split("^D=")[1]);
                        isAlphaNumeric(digest.get(digest.size() - 1));
                        System.out.println(line);
                    }
                    else{
                        endOfFil = true;
                    }
                }//while


                dsa.setX(new BigInteger(x));
                dsa.setY(new BigInteger(y));
                System.out.println("valid group");

                Iterator<String> it = digest.iterator();
                DSASignature d = new DSASignature();
                while(it.hasNext()){
                    System.out.println("Entering iterator");
                    Object obj = it.next();
                    String msg = (String)obj;
                    System.out.println(msg);
                    /* Generating a secureRandom in generateX or generateK does not work when called from this method
                    * not sure why. Note it is SecureRandom random = new SecureRandom() that is not working*/

                    d = dsa.sign(msg);
                    System.out.println("after sign");
                    System.out.println("s=" + d.getS());
                    System.out.println("r=" + d.getR());
                }
            }
            else if(line.equals("verify")){
                String y = (input.readLine().split("y="))[1];
                checkOnlyNumerals(y);
                boolean endOfFile = false;
                while(!endOfFile){
                    line = input.readLine();
                    if(line != null){
                        String digest = (line.split("D="))[1];
                        String r = (input.readLine().split("r="))[1];
                        String s = (input.readLine().split("s="))[1];

                        dsa.getUser().setY(new Key(new BigInteger(y)));
                        DSASignature sign = new DSASignature(new BigInteger(s),new BigInteger(r));
                        if(dsa.verify(dsa.getUser(),digest,sign)){
                            System.out.println("signature_valid");
                        }
                        else{
                            System.out.println("signature_invalid");
                        }
                    }
                    else{
                        endOfFile = true;
                    }
                }
            }
        }

        catch (IllegalArgumentException e){
            throw new IllegalArgumentException("Input not valid");
        }
        catch (Exception e){
            e.printStackTrace();
            throw new Exception("invalid_group");

        }
        finally{
            if(input != null){
                input.close();
            }
        }
    }
}
