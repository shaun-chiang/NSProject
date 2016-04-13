package com.example;


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
import java.io.InputStreamReader;
import java.lang.Exception;import java.lang.String;import java.lang.System;import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

/**
 * Created by Shaun on 11/4/2016.
 */
public class SecStoreClient {
    public static void main(String argv[]) {
        String sentence = "";
        String modifiedSentence;

        try {
            //establish connection
            Socket clientSocket = new Socket("localhost", 6789);
            //setup
            DataInputStream is = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
            DataOutputStream os = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
            //get and convert CA's certificate and public key
            InputStream fis2 = new FileInputStream("C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\CA.crt");
            CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
            X509Certificate CACert =(X509Certificate)cf2.generateCertificate(fis2);
            PublicKey CAKey = CACert.getPublicKey();

//
//            DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
//            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            //initial request
            System.out.println("initial request");
            String s = "Hello SecStore, please prove your identity!";
            sendData(os,s.getBytes());
            //receive from server
            byte[] M = receive(is); //this is supposed to be Ks- ("hello, this is SecStore!")
            System.out.println(Arrays.toString(M));
            //certificate request
            System.out.println("certificate request");
            s = "Give me your certificate signed by CA";
            sendData(os, s.getBytes());
            //get and convert server's certificate & public key
            byte[] certificate = receive(is); //this is supposed to be the certificate (signed)
            System.out.println(Arrays.toString(certificate));
            //write to certificate file
            FileOutputStream fos = new FileOutputStream("C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\clientreceivedcertificate.crt");
            fos.write(certificate);
            fos.close();

            //

            InputStream fis = new FileInputStream("C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\clientreceivedcertificate.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate ServerCert =(X509Certificate)cf.generateCertificate(fis);

            //check validity
            System.out.println("checking valid");
            ServerCert.checkValidity();
            ServerCert.verify(CAKey);

            //if it's valid, get the public key and decrypt the original message
            PublicKey key = ServerCert.getPublicKey();
            System.out.println("decrypt M");
            Cipher dcipher = Cipher.getInstance("RSA");
            dcipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypedbyte = dcipher.doFinal(M);
            if (!new String(decrypedbyte).equals("Hello, this is SecStore!")) {
                return;
            }

            System.out.println("pass successful, sending over file");
            s = "OK! I'm uploading now! (Handshake)";
            sendData(os, s.getBytes());

            //SEND THE FILE!
            try{
                //Create object of FileReader
                FileReader inputFile = new FileReader("C:\\Users\\Shaun\\Dropbox\\50-005\\NSProjectRelease\\sampleData\\smallFile.txt");
                //Instantiate the BufferedReader Class
                BufferedReader bufferReader = new BufferedReader(inputFile);
                //Variable to hold the one line data
                String line;
                // Read file line by line and print on the console
                while ((line = bufferReader.readLine()) != null)   {
                    sentence+=line;
                }
                //Close the buffer reader
                bufferReader.close();
                sendData(os,sentence.getBytes());
                modifiedSentence = new String(receive(is));
                System.out.println("From server: " + modifiedSentence);
            }catch(Exception e){
                System.out.println("Error while reading file line by line:" + e.getMessage());
            }


            System.out.println("Bye!");
            clientSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Bye! Something happened!");
        }

    }

    private static byte[] receive(DataInputStream is) {
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


    private static void sendData(DataOutputStream os, byte[] byteData) {
        try
        {
            os.write(byteData);
            os.flush();
        }
        catch (Exception exception)
        {
            exception.printStackTrace();
        }

    }
}
