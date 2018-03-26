/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.auteam.espaiencrip;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Properties;
import javax.crypto.SecretKey;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.crypto.CryptoHelper;

/**
 *
 * @author robihidayat
 */
public class Main {
    
        private static String encryptAlgorithm = "AES";
        private static int encryptionKeyLength = 128;
        private static String randomAlgorithm = "SHA1PRNG";
        
    public static void main(String[] args)throws Exception{   
        
        String encryptedPropFname = "";
        encryptedPropFname = args[0];
        
        if (args[1].equalsIgnoreCase("encode")){
            File f = new File(args[0]);
            ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY_SUCCESS, "Loading encrypted properties from " + f.getAbsolutePath() );
            if ( !f.exists() ) f.createNewFile();        
            ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY_SUCCESS, "Encrypted properties found in " + f.getAbsolutePath() );
            com.auteam.espaiencrip.DefaultEncryptedProperties ep = new com.auteam.espaiencrip.DefaultEncryptedProperties();
            FileInputStream in = null;
            FileOutputStream out = null;
            
            try {
                in = new FileInputStream(f);
                out = new FileOutputStream(f);
                ep.load(in);   
                    BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                    String key = null;
                    System.out.println("Masukan Key value yang akan di encrip yah !");
                    do {

                            System.out.print("Enter key: ");
                            key = br.readLine();
                            System.out.print("Enter value: ");
                            String value = br.readLine();
                            if (key != null && key.length() > 0 && value != null && value.length() > 0) {
                                    ep.setProperty(key, value);
                            }
                    } while (key != null && key.length() > 0);
                    ep.store(out, "Encrypted Properties File");


                } finally {
                    // FindBugs and PMD both complain about these next lines, that they may
                    // ignore thrown exceptions. Really!!! That's the whole point.
                try { if ( in != null ) in.close(); } catch( Exception e ) {}

                try { if ( out != null ) out.close(); } catch( Exception e ) {}
                }

                System.out.println("=======================================================");
                System.out.println("===================Encript Data========================");
                System.out.println("=======================================================");
                Iterator<?> i = ep.keySet().iterator();
                while (i.hasNext()) {
                    String k = (String) i.next();
                    String value = ep.getProperty(k);
                    System.out.println("   " + k + "=" + value);
            }
        } else if (args[1].equalsIgnoreCase("decode")) {
            try {
                DisplayEncryptedProperties dep = new DisplayEncryptedProperties();
                Properties props = new Properties();
                dep.loadProperties(encryptedPropFname, props);

            } catch(Throwable t) {
                System.err.println("Caught: " + t.getClass().getName() +
                                   "; exception msg: " + t);
                t.printStackTrace(System.err);
            }

        } else if (args[1].equalsIgnoreCase("masterkey")){
            System.out.println( "Generating a new secret master key" );

            // setup algorithms -- Each of these have defaults if not set, although
            //					   someone could set them to something invalid. If
            //					   so a suitable exception will be thrown and displayed.
            encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
            encryptionKeyLength = ESAPI.securityConfiguration().getEncryptionKeyLength();
            randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();

            SecureRandom random = SecureRandom.getInstance(randomAlgorithm);
            SecretKey secretKey = CryptoHelper.generateSecretKey(encryptAlgorithm, encryptionKeyLength);

            byte[] raw = secretKey.getEncoded();
            byte[] salt = new byte[20];	// Or 160-bits; big enough for SHA1, but not SHA-256 or SHA-512.
            random.nextBytes( salt );
            String eol = System.getProperty("line.separator", "\n"); // So it works on Windows too.
            System.out.println( eol + "Copy and paste these lines into your ESAPI.properties" + eol);
            System.out.println( "#==============================================================");
            System.out.println( "Encryptor.MasterKey=" + ESAPI.encoder().encodeForBase64(raw, false) );
            System.out.println( "Encryptor.MasterSalt=" + ESAPI.encoder().encodeForBase64(salt, false) );
            System.out.println( "#==============================================================" + eol);

        }else{
            System.out.println("Wrong Args");
        }
 
    }
       
}


