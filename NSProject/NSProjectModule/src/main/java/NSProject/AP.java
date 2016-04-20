package NSProject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.Exception;
import java.lang.String;
import java.lang.System;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/* THE AP CLASS:
    Equivalent to SecStore - this is the server.

    The handshake method we use is for the client to send a nonce
    over to the server so that the server can verify itself.
    Server will return the encrypted nonce, at which point client
    will request the certificate signed by CA from server.
    After decrypting the nonce using public key gotten from cert,
    client can verify server.


 */

public class AP {
    public static String filePath = "D:\\Documents\\NSProject\\NSProject\\ns_project\\";
    public static String fileOutputPath = "D:\\Documents\\NSProject\\NSProject\\ns_project\\outputs\\";
    public static int filesize;
    public static String clientSentence;

    public static void main(String argv[]) throws Exception {
        ServerSocket welcomeSocket = new ServerSocket(6789);
        System.out.println("*** Socket Initialized! ***");

        String privateKeyFileName = filePath+"privateServer.der";
        PrivateKey myPrivKey = getPrivKey(privateKeyFileName);

        System.out.println("*** Done with creating private key from privateServer.der ***");

        while (true) {
            Socket connectionSocket = welcomeSocket.accept();
            System.out.println("*** Client connected!***");
            boolean clientconnected = true;

            //Input and Output streams
            DataInputStream is = new DataInputStream(new BufferedInputStream(connectionSocket.getInputStream()));
            DataOutputStream os = new DataOutputStream(new BufferedOutputStream(connectionSocket.getOutputStream()));

            /*
               While this loop is running, the socket can sequentially take in
               more CP-1 or CP-2 clients.
             */
            while (clientconnected) {
                System.out.println("*** Awaiting responses from Client! ***");

                byte[] byteData = receiveData(is, "not data");

                clientSentence = new String(byteData, "UTF-8").trim();

                /*
                   The logic below checks which action to take.
                   1. "Hello SecStore, please prove your identity!"
                      SecStore will request a nonce, and as a first step to prove its authenticity.
                      It will then return an encrypted nonce.
                   2. "Give me your certificate signed by CA"
                      SecStore will send shaun_chiang.crt over to the client.
                      Client will then use this to decrypt the nonce and ensure that SecStore is
                      authentic.
                   3. "OK! I'm uploading now! (RSA/AES Handshake)"
                      File transfer process begins.
                 */
                System.out.println("*** Received clientSentence: " + clientSentence + " ***");

                if (clientSentence.equals("Hello SecStore, please prove your identity!")) {
                    byte[] gettingNonce = "Please send me a nonce".getBytes();

                    os.writeInt(gettingNonce.length);
                    os.write(gettingNonce);
                    os.flush();

                    byte[] byteDatanonce = receiveData(is, "not data");

                    System.out.println("    Received nonce... Encrypting now.");
                    byte[] encryptedNonce = encryptText(byteDatanonce, myPrivKey);

                    os.writeInt(encryptedNonce.length);
                    os.write(encryptedNonce);
                    os.flush();
                    System.out.println("    Encrypted nonce returned!");

                } else if (clientSentence.equals("Give me your certificate signed by CA")) {
                    System.out.println("*** Reading shaun_chiang.crt and sending over to client ***");
                    File cert = new File(filePath + "shaun_chiang.crt");
                    FileInputStream fis = new FileInputStream(cert);
                    byte[] certByte = new byte[(int) cert.length()];
                    fis.read(certByte);

                    os.writeInt(certByte.length);
                    os.write(certByte);
                    os.flush();
                    System.out.println("    Sent shaun_chiang.crt");

                } else if (clientSentence.trim().equals("OK! I'm uploading now! (RSA Handshake)")) {
                    /*
                       FILE TRANSFER (RSA)
                       - Client breaks data into chunks of 117 bytes and sends them over.
                     */

                    byte[] filenameData = receiveData(is, "not data");
                    String filename = new String(filenameData, "UTF-8").trim();
                    String[] tokens = new File(filename).getName().split("\\.(?=[^\\.]+$)");
                    boolean resolved= false;
                    String test = fileOutputPath + "RSA\\" + filename;
                    String sdf = new SimpleDateFormat("yyyy-MM-dd HHmm-ss").format(new Date());
                    while (!resolved) {
                        if (!(new File(test).exists())) {
                            resolved = true;
                        } else {
                            test = fileOutputPath+ "RSA\\"+tokens[0] +" duplicate created at "+ (sdf)+"."+tokens[1];
                            sdf = new SimpleDateFormat("yyyy-MM-dd HHmm-ss").format(new Date());
                        }
                    }

                    FileOutputStream fos = new FileOutputStream(test);
                    boolean stop = false;
                    while (!stop) {
                        byte[] filebyteData = receiveData(is, "RSA data");
                        clientSentence = new String(filebyteData, "UTF-8").trim();
                        if (clientSentence.trim().equals("Transmission Over!")) {
                            stop = true;
                        } else {
                            Cipher dcipher = Cipher.getInstance("RSA");
                            dcipher.init(Cipher.DECRYPT_MODE, myPrivKey);
                            byte[] decryptedbyte = dcipher.doFinal(filebyteData);

                            fos.write(decryptedbyte);
                        }
                    }
                    System.out.println("    File Closed");
                    fos.close();
                    System.out.println("*** Client Disconnected ***");
                    clientconnected = false;

                } else if (clientSentence.trim().equals("OK! I'm uploading now! (AES Handshake)")) {
                    /*
                       FILE TRANSFER (AES)
                       - Client simply reads file and sends entire chunk over.
                     */
                    byte[] filenameData = receiveData(is, "not data");
                    String filename = new String(filenameData, "UTF-8").trim();
                    String[] tokens = new File(filename).getName().split("\\.(?=[^\\.]+$)");
                    boolean resolved= false;
                    String test = fileOutputPath + "AES\\" + filename;
                    String sdf = new SimpleDateFormat("yyyy-MM-dd HHmm ss").format(new Date());
                    while (!resolved) {
                        if (!(new File(test).exists())) {
                            resolved = true;
                        } else {
                            test = fileOutputPath+ "AES\\" +tokens[0] +" duplicate created at "+ (sdf)+"."+tokens[1];
                            sdf = new SimpleDateFormat("yyyy-MM-dd HHmm ss").format(new Date());
                        }
                    }
                    byte[] nonceData = receiveData(is, "not data");

                    FileOutputStream fos = new FileOutputStream(test);
                    boolean stop = false;
                    while (!stop) {
                        byte[] filebyteData = receiveData(is, "AES data");
                        clientSentence = new String(filebyteData,"UTF-8");
                        if (clientSentence.trim().equals("Transmission Over!")) {
                            fos.close();
                            stop = true;
                        } else {
                            Cipher dcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                            dcipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(nonceData,"AES"));

                            System.out.println(filebyteData.length);

                            byte[] decryptedbyte = dcipher.doFinal(filebyteData);
                            clientSentence = new String(decryptedbyte);
                            System.out.println(clientSentence);

                            fos.write(decryptedbyte);
                        }
                    }
                    System.out.println("    File Closed");
                    System.out.println("*** Client Disconnected ***");
                    clientconnected = false;
                } else if (clientSentence.equals("Bye!")) {
                    System.out.println("*** Client Disconnected ***");
                    clientconnected = false;
                } else {
                    System.out.println("*** Either a wrong message is received... ***");
                    System.out.println("*** Or the above two actions are donee... ***");
                }
            }
        }
    }

    private static byte[] receiveData(DataInputStream is, String type) throws Exception {
        int length = is.readInt();
        filesize = length;

        System.out.println("        length is " + length + " and type is " + type);
        try {
            if(type.equals("AES data")) {
                byte[] inputData = new byte[length];
                is.readFully(inputData);
                byte[] newData = inputData;
                return newData;

            } else if(type.equals("RSA data")) {
                byte[] inputData = new byte[128];
                is.read(inputData);
                byte[] newData = inputData;
                return newData;
            }
            else {
                byte[] inputData = new byte[length];
                is.read(inputData, 0, length);
                return inputData;
            }
        }
        catch (Exception exception) {
            exception.printStackTrace();
        }
        return null;
    }

    private static byte[] encryptText(byte[] text, PrivateKey myPrivKey) {
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance("RSA");
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, myPrivKey);
            byte[] cipherText = cipher.doFinal(text);
            System.out.println("        on EncryptText: returning cipherText");
            return cipherText;
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("        on EncryptText: returning null :(");
        return null;
    }

    public static PrivateKey getPrivKey(String filename)
            throws Exception {

        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
}
