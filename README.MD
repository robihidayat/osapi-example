
#Project OWASP ESAPI 

    Requirment:
    
    <dependency>
      <groupId>org.owasp.esapi</groupId>
      <artifactId>esapi</artifactId>
      <version>2.1.0.1</version>
    </dependency>

    How to Use : 
    
    A. Make Master Key 
    
    Define Parameter: 

        private static String encryptAlgorithm = "AES";
        private static int encryptionKeyLength = 128;
        private static String randomAlgorithm = "SHA1PRNG";
    
        encryptAlgorithm = ESAPI.securityConfiguration().getEncryptionAlgorithm();
        encryptionKeyLength = ESAPI.securityConfiguration().getEncryptionKeyLength();
        randomAlgorithm = ESAPI.securityConfiguration().getRandomAlgorithm();

        SecureRandom random = SecureRandom.getInstance(randomAlgorithm);
        SecretKey secretKey = CryptoHelper.generateSecretKey(encryptAlgorithm, encryptionKeyLength);
        
        byte[] raw = secretKey.getEncoded();
        byte[] salt = new byte[20];	
        random.nextBytes( salt );
        String eol = System.getProperty("line.separator", "\n"); // So it works on Windows too.
        System.out.println( eol + "Copy and paste these lines into your ESAPI.properties" + eol);
        System.out.println( "#==============================================================");
        System.out.println( "Encryptor.MasterKey=" + ESAPI.encoder().encodeForBase64(raw, false) );
        System.out.println( "Encryptor.MasterSalt=" + ESAPI.encoder().encodeForBase64(salt, false) );
        System.out.println( "#==============================================================" + eol);


        
    B. Encript 

        org.owasp.esapi.reference.crypto.DefaultEncryptedProperties ep = new org.owasp.esapi.reference.crypto.DefaultEncryptedProperties;
        
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

    C. Decript 