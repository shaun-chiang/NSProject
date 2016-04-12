package com.example;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.Exception;import java.lang.String;import java.lang.System;import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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
            DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            //request
            System.out.println("initial request");
            String s = "Hello SecStore, please prove your identity!" + "\n";
            outToServer.writeBytes(s);
            String M = inFromServer.readLine(); //this is supposed to be Ks- ("hello, this is SecStore!")
            System.out.println(M);
            //certificate request
            System.out.println("certificate request");
            s = "Give me your certificate signed by CA" + "\n";
            outToServer.writeBytes(s);
            String certificate = inFromServer.readLine(); //this is supposed to be the certificate (signed)
            InputStream fis = new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8));;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
            System.out.println("checking valid");
            CAcert.checkValidity();
            outToServer.writeBytes("OK! I'm uploading now! (Handshake)"+"\n");

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
                outToServer.writeBytes(sentence + '\n');
                modifiedSentence = inFromServer.readLine();
                System.out.println("From server (Capitalised): " + modifiedSentence);
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
}
