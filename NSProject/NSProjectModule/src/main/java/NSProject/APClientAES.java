package NSProject;

import com.sun.org.apache.xpath.internal.SourceTree;
import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by kisa on 18/4/2016.
 */
public class APClientAES {

    //CHANGE THIS TO FIT YOUR OWN COMPUTER
    public static String filePath = "D:\\Documents\\NSProject\\NSProject\\ns_project\\";
    public static int byteArrayLength;
    public static String nonce;


    public static void main(String argv[]) {
        try {
            //Establish Connection
            Socket clientSocket = new Socket("10.12.23.60", 6789);
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
            String nonceToCompare = new String(decryptedNonce,"UTF-8");
            System.out.println("    Returned nonce is: " + nonceToCompare);
            if(nonce.equals(nonceToCompare)) {
                System.out.println("*** RETURNED NONCE IS SAME AS SENT ***");
                System.out.println("    Server authenticated!");

                //START FILE UPLOAD
                byte[] handshake = "OK! I'm uploading now! (AES Handshake)".getBytes();
                os.writeInt(handshake.length);
                os.write(handshake);
                os.flush();

                System.out.println("*** Beginning file transfer ***");

                //VARY THIS FILE TO TRANSFER DIFFERENT FILE TYPES
                String file = "charspritesheet.png";

                File fileToSend = new File(filePath + "\\sampleData\\" +file);
                InputStream fis3 = new FileInputStream(fileToSend);
                byte[] fileToSendbytes = new byte[(int) fileToSend.length()];
                fis3.read(fileToSendbytes);

                System.out.println("    Sending filename over...");
                byte[] filename = (file).getBytes("UTF-8");
                os.writeInt(filename.length);
                os.write(filename);
                os.flush();

                System.out.println("    Sending key over...");
                SecretKey ftnonce = KeyGenerator.getInstance("AES").generateKey();
                MessageDigest sha = MessageDigest.getInstance("SHA-1");
                byte[] ftnoncebytes = sha.digest(ftnonce.getEncoded());
                ftnoncebytes = Arrays.copyOf(ftnoncebytes,16);
                os.writeInt(ftnoncebytes.length);
                os.write(ftnoncebytes);
                os.flush();


                System.out.println("    Sending encrypted file over...");

                encryptAESsend(fileToSendbytes, os, ftnoncebytes);

                System.out.println("    Sent encrypted file");
                clientSocket.close();
                System.out.println("*** Socket closed! ***");

            } else {
                System.out.println("*** RETURNED NONCE NOT SAME AS SENT ***");
                System.out.println("    Server authentication failed :(");

                System.out.println("    Sending Bye!");
                byte[] bye = "Bye!".getBytes();
                os.writeInt(bye.length);
                os.write(bye);
                os.flush();
                clientSocket.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //This method receives data from the server
    private static byte[] receive(DataInputStream is, int length) {
        try {
            byte[] inputData = new byte[length];
            is.read(inputData);
            return inputData;
        }
        catch (Exception exception){
            exception.printStackTrace();
        }
        return null;
    }

    //This method encrypts and sends the byte array
    private static void encryptAESsend (byte[] array, DataOutputStream os, byte[] key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] encryptedbyte;

        encryptedbyte = cipher.doFinal(array);
        os.writeInt(encryptedbyte.length);
        os.write(encryptedbyte);
        os.flush();
        encryptedbyte= "Transmission Over!".getBytes();
        os.writeInt(encryptedbyte.length);
        os.write(encryptedbyte);
        os.flush();
    }

    //This method generates nonce
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
