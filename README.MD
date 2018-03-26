
# Project OWASP ESAPI 

untuk bisa menggunakan OWASP ESAPI kita perlu menambahkan dependensi pada pom.xml, bisa anda menggunakan mavan builder. 
version yang dipakai adalah 2.1.0.1. 

    Requirment:
    
    <dependency>
      <groupId>org.owasp.esapi</groupId>
      <artifactId>esapi</artifactId>
      <version>2.1.0.1</version>
    </dependency>

## Cara menggunakannya

### Pertama kita generate Master Key. 
    
    Master Key tersebut digunakan untuk proses Encripsi dan Proses Decripsi. 
    
### Requriemt
    
    Pertama siapkan file log4j.xml, validation.properties, ESPI.properties. lalu masukan pada folder di home. 
    file tersebut bisa didapatkan dari link berikut [https://github.com/ESAPI/esapi-java-legacy/tree/develop/src/test/resources]

A. Make Master Key 

    Tahap kedua adalah generate Master key, berikut potongan source code untuk generate Master Key: 

    // Define Parameter: 
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
    
berikut potongan source code untuk encript file properties tersebut: 

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

Pada dasarnya source code encript tersebut menggunakan class org.owasp.esapi.reference.crypto.DefaultEncryptedProperties. 

C. Decript 

Pada main program, Proses Decript sebenarnya ada di class DisplayEncryptedProperties, hanya saja di jalankan pada main. 
        
        try{
            DisplayEncryptedProperties dep = new DisplayEncryptedProperties();
            Properties props = new Properties();
            dep.loadProperties(encryptedPropFname, props);
        }  catch(Throwable t) {
            System.err.println("Caught: " + t.getClass().getName() + "; exception msg: " + t);
        t.printStackTrace(System.err); 
        }

dimana function pada DefaultEncryptedProperties adalah sebagai berikut: 

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

dan untuk menjalankan program tersebut setelah di compile: 

        java -Dlog4j.configuration=file:/Users/robihidayat/NetBeansProjects/esapi-java-legacy/src/test/resources/log4j.xml -jar target/EspaiEncrip-1.0-SNAPSHOT.jar encrypted.properties