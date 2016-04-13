package com.example;

import java.io.BufferedReader;
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
            InputStream fis = new FileInputStream("C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);
            //Extract public key
            PublicKey key = CAcert.getPublicKey();

            String privateKeyFileName = "C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\ns_project\\privateServer.der";
            Path path = Paths.get(privateKeyFileName);
            byte[] privKeyByteArray = Files.readAllBytes(path);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
            System.out.println("done with stuff");


            while (true) {

                Socket connectionSocket = welcomeSocket.accept();
                BufferedReader inFromClient = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
                DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
                System.out.println("waiting");
                clientSentence = inFromClient.readLine().trim();
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
                    outToClient.writeBytes(String.valueOf(cipherText)+'\n');
                    System.out.println("done!");
                } else if (clientSentence.trim().equals("Give me your certificate signed by CA")) {
                    System.out.println("second part");
                    //send server's signed certificate
                    outToClient.writeBytes(String.valueOf(fis)+"\n");
                } else if (clientSentence.trim().equals("OK! I'm uploading now! (Handshake)")) {
                    System.out.println("last part");
                    clientSentence = inFromClient.readLine();
                    System.out.println("Received: " + clientSentence);
                    capitalizedSentence = clientSentence.toUpperCase() + '\n';
                    outToClient.writeBytes(capitalizedSentence);
                }
                welcomeSocket.close();



            }
        } catch (Exception e) {
            e.printStackTrace();
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
