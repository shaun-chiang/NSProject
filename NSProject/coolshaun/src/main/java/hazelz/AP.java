package hazelz;

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
import java.lang.Exception;import java.lang.String;import java.lang.System;
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
import java.util.Arrays;

import javax.crypto.Cipher;
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

    public static String clientSentence;

    public static void main(String argv[]) throws Exception {
        ServerSocket welcomeSocket = new ServerSocket(6789);
        System.out.println("*** Socket Initialized! ***");

        String publicKeyFileName = filePath+"publicServer.der";
        PublicKey pubKey = getPubKey(publicKeyFileName);

        String privateKeyFileName = filePath+"privateServer.der";
        PrivateKey myPrivKey = getPrivKey(privateKeyFileName);

        System.out.println("*** Done with creating public key and private key from privateServer.der and publicServer.der ***");

        Socket connectionSocket = welcomeSocket.accept();
        System.out.println("*** Client connected!***");

        //Input and Output streams
        DataInputStream is = new DataInputStream(new BufferedInputStream(connectionSocket.getInputStream()));
        DataOutputStream os = new DataOutputStream(new BufferedOutputStream(connectionSocket.getOutputStream()));

        while(true) {
            System.out.println("*** Awaiting responses from Client! ***");

            byte[] byteData = receiveData(is, "not data");

            clientSentence = new String(byteData).trim();
            System.out.println("*** Received clientSentence: " + clientSentence + " ***");

            if(clientSentence.equals("Hello SecStore, please prove your identity!")) {
                byte[] gettingNonce = "Please send me a nonce".getBytes();

                os.writeInt(gettingNonce.length);
                os.write(gettingNonce);
                os.flush();

                byteData = receiveData(is, "not data");

                System.out.println("    Received nonce... Encrypting now.");
                byte[] encryptedNonce = encryptText(byteData, myPrivKey);

                os.writeInt(encryptedNonce.length);
                os.write(encryptedNonce);
                os.flush();
                System.out.println("    Encrypted nonce returned!");

            } if(clientSentence.equals("Give me your certificate signed by CA")) {
                System.out.println("*** Reading shaun_chiang.crt and sending over to client ***");
                File cert = new File(filePath + "shaun_chiang.crt");
                FileInputStream fis = new FileInputStream(cert);
                byte[] certByte = new byte[(int) cert.length()];
                fis.read(certByte);

                os.writeInt(certByte.length);
                os.write(certByte);
                os.flush();
                System.out.println("    Sent shaun_chiang.crt");
            } else if (clientSentence.trim().equals("OK! I'm uploading now! (Handshake)")) {
                //FILE UPLOAD?
                byte[] filenameData = receiveData(is, "not data");
                String filename = new String(filenameData).trim();
                FileOutputStream fos=new FileOutputStream(fileOutputPath + filename);
                boolean stop = false;
                while(!stop) {
                    byte[] filebyteData = receiveData(is, "data");
                    clientSentence = new String(filebyteData).trim();
                    if(clientSentence.trim().equals("Transmission Over!")) {
                        stop = true;
                    } else {
                        Cipher dcipher = Cipher.getInstance("RSA");
                        dcipher.init(Cipher.DECRYPT_MODE, myPrivKey);
                        //System.out.println(Arrays.copyOfRange(filebyteData, 0, 117).length);
                        byte[] decryptedbyte = dcipher.doFinal(filebyteData);

                        fos.write(decryptedbyte);
                    }
                }
                System.out.println("    File Closed");
                fos.close();
            } else {
                System.out.println("*** Either a wrong message is received... ***");
                System.out.println("*** Or the above two actions are donee... ***");
            }

        }

    }

    private static void sendData(DataOutputStream os, byte[] byteData) {
        if (byteData == null) {return;}
        try {
            os.write(byteData);
            os.flush();
        }
        catch (Exception exception) {
        }
    }


    private static byte[] receiveData(DataInputStream is, String type) throws Exception {
        int length = is.readInt();
        System.out.println("        length is " + length + " and type is " + type);
        try {
            if(type.equals("data")) {
                byte[] inputData = new byte[128];
                is.read(inputData, 0, length);
                return inputData;

            } else {
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

    public static PublicKey getPubKey(String filename)
            throws Exception {

        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
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
    private static byte[] decryptWithLimits(byte[] array, X509Certificate CACert) throws Exception {
        PublicKey key = CACert.getPublicKey();
        System.out.println("decrypt in parts");
        Cipher dcipher = Cipher.getInstance("RSA");
        dcipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedbyte = new byte[array.length];
        System.out.println("length of array is " + array.length);
        int numberOfArrays = (array.length/128);
        for(int i = 0; i<numberOfArrays; i++) {
            if(i == numberOfArrays-1) {
                System.out.println("decipher from " + i*128 + " to " + (array.length-1));
                decryptedbyte = dcipher.update(Arrays.copyOfRange(array, i * 128, array.length - 1));
                System.out.println(Arrays.toString(decryptedbyte));

            } else {
                System.out.println("decipher from " + i*128 + " to " + ((i+1)*128-1));
                decryptedbyte = dcipher.update(Arrays.copyOfRange(array, i * 128, ((i + 1) * 128)-1));

            }

        }
        decryptedbyte = dcipher.doFinal(decryptedbyte);
        System.out.println(new String(decryptedbyte));
        return decryptedbyte;
    }
}
