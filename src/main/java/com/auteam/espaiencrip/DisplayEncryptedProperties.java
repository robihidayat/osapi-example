/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.auteam.espaiencrip;
import java.io.*;
import java.util.*;
import org.owasp.esapi.EncryptedProperties;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.reference.crypto.DefaultEncryptedProperties;

// Purpose: Short code snippet to show how to display encrypted property files
//          that were encrypted using ESAPI's EncryptedProperties class.
//
// Usage: java -classpath <cp> DisplayEncryptedProperties encryptedPropFileName
//        where <cp> is proper classpath, which minimally include esapi.jar & log4j.jar
public class DisplayEncryptedProperties {

    public DisplayEncryptedProperties() {
    }

    public void loadProperties(String encryptedPropertiesFilename,
                                  Properties props )
        throws IOException, EncryptionException
    {
         EncryptedProperties loader = new DefaultEncryptedProperties();
         loader.load( new FileInputStream(
                                    new File( encryptedPropertiesFilename) ) );
         
        Iterator<?> i = loader.keySet().iterator();
        while (i.hasNext()) {
            String k = (String) i.next();
            String value = loader.getProperty(k);
            System.out.println("   " + k + "= "+value);
        }
        

    }

    public void showProperties(Properties props) throws Exception
    {
        System.out.println("");
        String value = null;
        value = props.getProperty( "database.driver");
        System.out.println("database.driver=" + value);
        value = props.getProperty( "jdbc.url");
        System.out.println("jdbc.url=" + value);
        value = props.getProperty( "jdbc.username");
        System.out.println("jdbc.username=" + value);
        value = props.getProperty( "jdbc.password");
        System.out.println("jdbc.password=" + value);
    }


    public static void main(String[] args) {

        try {
            DisplayEncryptedProperties dep = new DisplayEncryptedProperties();
            Properties props = new Properties();

            String encryptedPropFname = "encrypted.properties";
            if ( args.length == 1 ) {
                encryptedPropFname = args[0];
            } else {
                System.err.println("Usage: java -classpath <cp> DisplayEncryptedProperties encryptedPropFileName");
                System.exit(2);
            }

            dep.loadProperties(encryptedPropFname, props);
            dep.showProperties(props);

        } catch(Throwable t) {
            System.err.println("Caught: " + t.getClass().getName() +
                               "; exception msg: " + t);
            t.printStackTrace(System.err);
        }
    }
}

