package com.example;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
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

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

/**
 * Created by Shaun on 11/4/2016.
 */
public class SecStore {

    public static void main(String argv[]){
        try {
            String clientSentence;
            String capitalizedSentence;
            ServerSocket welcomeSocket = new ServerSocket(6789);

            //create X509certificate object
//            InputStream fis = new FileInputStream("C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\ChiangZhiMinShaun.csr");
            byte[] signedcert = Files.readAllBytes(Paths.get("C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\Shaun_Chiang.crt"));

            String privateKeyFileName = "C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\ns_project\\privateServer.der";
            Path path = Paths.get(privateKeyFileName);
            byte[] privKeyByteArray = Files.readAllBytes(path);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
            System.out.println("done with stuff");
            Socket connectionSocket = welcomeSocket.accept();

            DataInputStream is = new DataInputStream(new BufferedInputStream(connectionSocket.getInputStream()));
            DataOutputStream os = new DataOutputStream(new BufferedOutputStream(connectionSocket.getOutputStream()));

//
//            BufferedReader inFromClient = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
//            BufferedOutputStream outToClient = new BufferedOutputStream(connectionSocket.getOutputStream());



            while (true) {
                System.out.println("waiting");
                byte[] byteData = receiveData(is);
                clientSentence = new String(byteData).trim();
                if (clientSentence.trim().equals("Hello SecStore, please prove your identity!")) {
                    System.out.println("first part");
                    //send private key encrypt ("Hello, this is SecStore!")
                    byte[] cipherText = null;
                    try {
                        // get an RSA cipher object and print the provider
                        final Cipher cipher = Cipher.getInstance("RSA");
                        // encrypt the plain text using the public key
                        cipher.init(Cipher.ENCRYPT_MODE, myPrivKey);
                        cipherText = cipher.doFinal("Hello,this is SecStore!".getBytes());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    String base64format = DatatypeConverter.printBase64Binary(cipherText);
                    sendData(os,cipherText);
                    System.out.println("done!");
                } else if (clientSentence.trim().equals("Give me your certificate signed by CA")) {
                    System.out.println("second part");
                    //send server's signed certificate
                    sendData(os,signedcert);
                } else if (clientSentence.trim().equals("OK! I'm uploading now! (Handshake)")) {
                    System.out.println("last part");
                    byteData = receiveData(is);
                    clientSentence = new String(byteData).trim();
                    System.out.println("Received: " + clientSentence);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendData(DataOutputStream os, byte[] byteData) {
        if (byteData == null)
        {
            return;
        }
        try
        {
            os.write(byteData);
            os.flush();
        }
        catch (Exception exception)
        {
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


    private static byte[] receiveData(DataInputStream is) throws Exception {
        try
        {
            byte[] inputData = new byte[1024];
            is.read(inputData);
            return inputData;
        }
        catch (Exception exception)
        {
            exception.printStackTrace();
        }
        return null;
    }
}
