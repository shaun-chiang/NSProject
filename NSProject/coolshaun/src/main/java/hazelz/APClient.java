package hazelz;

import com.sun.org.apache.xpath.internal.SourceTree;
import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;

/**
 * Created by kisa on 18/4/2016.
 */
public class APClient {
    public static String filePath = "C:\\Users\\Shaun\\Documents\\NSProject\\NSProject\\ns_project\\";
    public static int byteArrayLength;
    public static String nonce;

    public static void main(String argv[]) {
        String sentence = "";
        String modifiedSentence;

        try {
            //Establish Connection
            Socket clientSocket = new Socket("localhost", 6789);
            System.out.println("*** Connected to Server! Is this the legitimate Server? ***");

            //Input and Output streams
            DataInputStream is = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
            DataOutputStream os = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));

            //get and convert CA's certificate and public key
            InputStream fis2 = new FileInputStream(filePath + "CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CACert = (X509Certificate) cf.generateCertificate(fis2);
            PublicKey CAKey = CACert.getPublicKey();

            System.out.println("*** Requesting proof of Identity ***");
            byte[] identityCheck = "Hello SecStore, please prove your identity!".getBytes();
            os.writeInt(identityCheck.length);
            os.write(identityCheck);
            os.flush();

            byteArrayLength = is.readInt();
            byte[] receivedData = receive(is, byteArrayLength);

            if(new String(receivedData).trim().equals("Please send me a nonce")) {
                System.out.println("*** Server requests a nonce ***");
                nonce = generateNonce();
                byte[] nonceArray = nonce.getBytes();
                os.writeInt(nonceArray.length);
                os.write(nonceArray);
                os.flush();
            }

            System.out.println("*** Awaiting encrypted nonce... ***");
            byteArrayLength = is.readInt();
            byte[] receivedEncryptedNonce = receive(is, byteArrayLength);

            System.out.println("*** Requesting signed certificate from Server ***");
            byte[] requestForCert = "Give me your certificate signed by CA".getBytes();
            os.writeInt(requestForCert.length);
            os.write(requestForCert);
            os.flush();

            byteArrayLength = is.readInt();
            byte[] receivedCert = receive(is, byteArrayLength);

            X509Certificate signedCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(receivedCert));

            System.out.println("*** Received certificate... Checking Validity now ***");
            signedCert.checkValidity();
            signedCert.verify(CAKey);
            PublicKey serverPublicKey = signedCert.getPublicKey();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
            byte[] decryptedNonce = cipher.doFinal(receivedEncryptedNonce);
            String nonceToCompare = new String(decryptedNonce);
            System.out.println("    Returned nonce is: " + nonceToCompare);
            if(nonce.equals(nonceToCompare)) {
                System.out.println("*** RETURNED NONCE IS SAME AS SENT ***");
                System.out.println("    Server authenticated!");

                //START FILE UPLOAD
                byte[] handshake = "OK! I'm uploading now! (Handshake)".getBytes();
                os.writeInt(handshake.length);
                os.write(handshake);
                os.flush();

                System.out.println("*** Beginning file transfer ***");
                String file = "smallFile.txt";
                File fileToSend = new File(filePath + file);
                InputStream fis3 = new FileInputStream(fileToSend);
                byte[] fileToSendbytes = new byte[(int) fileToSend.length()];
                fis3.read(fileToSendbytes);

                byte[] filename = (file).getBytes();
                os.writeInt(filename.length);
                os.write(filename);
                os.flush();

                encryptWithLimitsandSend(fileToSendbytes, signedCert, os);

                System.out.println("    Sent encrypted file");


            } else {
                System.out.println("*** RETURNED NONCE NOT SAME AS SENT ***");
                System.out.println("    Server authentication failed :(");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] receive(DataInputStream is, int length) {
        try
        {
            byte[] inputData = new byte[length];
            is.read(inputData);
            return inputData;
        }
        catch (Exception exception)
        {
            exception.printStackTrace();
        }
        return null;
    }


    private static void sendData(DataOutputStream os, byte[] byteData) {
        try {
            os.write(byteData);
            os.flush();
        }
        catch (Exception exception)
        {
            exception.printStackTrace();
        }

    }


    private static void encryptWithLimitsandSend(byte[] array, X509Certificate CACert, DataOutputStream os) throws Exception {
        PublicKey key = CACert.getPublicKey();
        System.out.println("encrypt with limits");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedbyte = new byte[array.length];
        System.out.println("length of array is " + array.length);
        System.out.println("Array is: " + Arrays.toString(array));
        int numberOfArrays = (int)Math.ceil(array.length/117.0);
        for(int i = 0; i<numberOfArrays; i++) {
            if(i == numberOfArrays-1) {
                System.out.println("cipher from " + i*117 + " to " + (array.length-1)+" : "+((array.length-1)-i*117));
                encryptedbyte = cipher.doFinal(Arrays.copyOfRange(array, i * 117, array.length - 1));
                System.out.println(Arrays.toString(encryptedbyte));
                os.writeInt(encryptedbyte.length);
                os.write(encryptedbyte);
                os.flush();
                encryptedbyte= "Transmission Over!".getBytes();
                os.writeInt(encryptedbyte.length);
                os.write(encryptedbyte);
                os.flush();

            } else {
                System.out.println("cipher from " + i*117 + " to " + ((i+1)*117-1)+ " : "+((((i + 1) * 117)-1)-i*117));
                encryptedbyte = cipher.doFinal(Arrays.copyOfRange(array, i * 117, ((i + 1) * 117) - 1));
                System.out.println(Arrays.toString(encryptedbyte));
                os.writeInt(encryptedbyte.length);
                os.write(encryptedbyte);
                os.flush();
            }

        }
    }

    public static String generateNonce() {
        SecureRandom sr;
        try {
            sr = SecureRandom.getInstance("SHA1PRNG");
            String nonce = new BigInteger(130, sr).toString();

            return nonce;

        } catch (NoSuchAlgorithmException e) {
        }
        return null;
    }
}
