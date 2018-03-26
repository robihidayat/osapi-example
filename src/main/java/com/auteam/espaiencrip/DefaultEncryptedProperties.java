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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.crypto.CipherText;
import org.owasp.esapi.crypto.PlainText;
import org.owasp.esapi.errors.EncryptionException;

/**
 *
 * @author robihidayat
 */
public class DefaultEncryptedProperties implements org.owasp.esapi.EncryptedProperties{

    /** The properties. */
	private final Properties properties = new Properties();

	/** The logger. */
	private final Logger logger = ESAPI.getLogger("EncryptedProperties");

	/**
	 * Instantiates a new encrypted properties.
	 */
	public DefaultEncryptedProperties() {
		// hidden
	}

    @Override
    public synchronized String getProperty(String key) throws EncryptionException {
        String[] errorMsgs = new String[] {
	            ": failed decoding from base64",
	            ": failed to deserialize properly",
	            ": failed to decrypt properly"
	        };
        int progressMark = 0;
	    try {
	        String encryptedValue = properties.getProperty(key);

	        if(encryptedValue==null)
	            return null;

	        progressMark = 0;
	        byte[] serializedCiphertext   = ESAPI.encoder().decodeFromBase64(encryptedValue);
	        progressMark++;
	        CipherText restoredCipherText = CipherText.fromPortableSerializedBytes(serializedCiphertext);
	        progressMark++;
	        PlainText plaintext           = ESAPI.encryptor().decrypt(restoredCipherText);
	        
	        return plaintext.toString();
	    } catch (Exception e) {
	        throw new EncryptionException("Property retrieval failure",
	                                      "Couldn't retrieve encrypted property for property " + key +
	                                      errorMsgs[progressMark], e);
	    }
    }

    @Override
    public synchronized String setProperty(String key, String value) throws EncryptionException {
            String[] errorMsgs = new String[] {
	            ": failed to encrypt properly",
	            ": failed to serialize correctly",
	            ": failed to base64-encode properly",
	            ": failed to set base64-encoded value as property. Illegal key name?"
	    };

	    int progressMark = 0;
	    try {
	        if ( key == null ) {
	            throw new NullPointerException("Property name may not be null.");
	        }
	        if ( value == null ) {
	            throw new NullPointerException("Property value may not be null.");
	        }
	        // NOTE: Not backward compatible w/ ESAPI 1.4.
	        PlainText pt = new PlainText(value);
	        CipherText ct = ESAPI.encryptor().encrypt(pt);
               // System.out.println("ct : "+ct);
	        progressMark++;
                System.out.println("CipherText getCipherMode : "+ct.getCipherMode());
                System.out.println("CipherText getBase64EncodedRawCipherText : "+ct.getBase64EncodedRawCipherText());
                System.out.println("CipherText getCipherTransformation : "+ct.getCipherTransformation());
                System.out.println("CipherText getEncryptionTimestamp : "+ct.getEncryptionTimestamp());
                System.out.println("CipherText asPortableSerializedByteArray : "+Arrays.toString(ct.asPortableSerializedByteArray()));
                System.out.println("CipherText getSeparateMAC : "+Arrays.toString(ct.getSeparateMAC()));
                System.out.println("CipherText getEncodedIVCipherText : "+ct.getEncodedIVCipherText());

                

	        byte[] serializedCiphertext = ct.asPortableSerializedByteArray();
               // System.out.println("serializedCiphertext : "+Arrays.toString(serializedCiphertext));
	        progressMark++;
	        String b64str = ESAPI.encoder().encodeForBase64(serializedCiphertext, false);
                System.out.println("b64str : "+b64str);
	        progressMark++;
	        String encryptedValue = (String)properties.setProperty(key, b64str);
                //System.out.println("encryptedValue : "+encryptedValue);
	        progressMark++;
	        return encryptedValue;
	    } catch (Exception e) {
	        throw new EncryptionException("Property setting failure",
	                                      "Couldn't set encrypted property " + key +
	                                      errorMsgs[progressMark], e);
	    }
    }

    @Override
    public Set<?> keySet() {
        return properties.keySet();    
    }

    @Override
    public void load(InputStream in) throws IOException {
        properties.load(in);
        logger.trace(Logger.SECURITY_SUCCESS, "Encrypted properties loaded successfully");
    }

    @Override
    public void store(OutputStream out, String comments) throws IOException {
            properties.store(out, comments);
    }
    
    @Deprecated
        public static void main(String[] args) throws Exception {
            File f = new File(args[0]);
            ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY_SUCCESS, "Loading encrypted properties from " + f.getAbsolutePath() );
            if ( !f.exists() ) throw new IOException( "Properties file not found: " + f.getAbsolutePath() );
            ESAPI.getLogger( "EncryptedProperties.main" ).debug(Logger.SECURITY_SUCCESS, "Encrypted properties found in " + f.getAbsolutePath() );
            org.owasp.esapi.reference.crypto.DefaultEncryptedProperties ep = new org.owasp.esapi.reference.crypto.DefaultEncryptedProperties();

            FileInputStream in = null;
            FileOutputStream out = null;
            try {
            in = new FileInputStream(f);
            out = new FileOutputStream(f);

            ep.load(in);   
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            String key = null;
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

            Iterator<?> i = ep.keySet().iterator();
            while (i.hasNext()) {
                String k = (String) i.next();
                String value = ep.getProperty(k);
                System.out.println("   " + k + "=" + value);
            }
    }

    
}
