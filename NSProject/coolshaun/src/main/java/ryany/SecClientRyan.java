package ryany;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Random;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

/**
 * Created by Nayr on 13/4/2016.
 */
public class SecClientRyan {
    public final static String FILE_TO_RECEIVED = "E:\\Term 5\\50-005\\Week 11\\NSProjectRelease\\sampleData\\largeFile.txt";
    public final static int FILE_SIZE = 6022386;
    public static File fileToSend;

    public static String filePath = "D:\\Documents\\NSProject\\NSProject\\ns_project\\";

    public static void main(String[] args) {
        try {
            //Extracting of CSE CA Public Key Used to decrypt Signed Certificate
            InputStream fis = new FileInputStream(filePath+"CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate)cf.generateCertificate(fis);
            PublicKey CAkey = CAcert.getPublicKey();

            String hostName = "localhost";
            int portNumber = 4321;

            Socket echoSocket = new Socket(hostName, portNumber);
            DataOutputStream out = new DataOutputStream(echoSocket.getOutputStream());
            DataInputStream in =
                    new DataInputStream (echoSocket.getInputStream());
            BufferedReader stdIn =
                    new BufferedReader(
                            new InputStreamReader(System.in));

            // Client input for file to send
            System.out.println("Enter file to send to server: ");
            fileToSend = new File(stdIn.readLine());

            // Authenticate server
            // Generate nounce and send to server
            String nounce = new Random().nextInt() + "";
//            String nounce = "hello";
            System.out.println(nounce);
            out.writeInt(nounce.getBytes().length);
            out.write(nounce.getBytes());
            out.flush();

            // Receive encrypted nounce
            int len = in.readInt();
            byte[] encryptedNounce = new byte[len];
            in.read(encryptedNounce, 0, len);

            // Receive signed cert from server
            int certLen = in.readInt();
            byte[] serverCert = new byte[certLen];
            in.read(serverCert);

            X509Certificate signedCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(serverCert));

            // Check server sert and verify encrypted nounce
            signedCert.checkValidity();
            signedCert.verify(CAkey);
            PublicKey serverPublicKey = signedCert.getPublicKey();
            Cipher ecipher = Cipher.getInstance("RSA");
            ecipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
            byte[] decryptedNounce = ecipher.doFinal(encryptedNounce);
            String returnedNounce = new String(decryptedNounce);
            System.out.println(returnedNounce);
            if (nounce.equals(returnedNounce))
                System.out.println("Server authenticated");
            else
                System.out.println("Server authentication failed. Aborting...");

            in.close();
            out.close();
            stdIn.close();

            //After Receiving the file, get back the server cert using byte array
           /* byte [] mybytearray  = new byte [FILE_SIZE];
            InputStream is = echoSocket.getInputStream();
            FileOutputStream fos = new FileOutputStream(FILE_TO_RECEIVED);
            BufferedOutputStream bos = new BufferedOutputStream(fos);
            int bytesRead = is.read(mybytearray,0,mybytearray.length);
            int current = bytesRead;

            do {
                bytesRead =
                        is.read(mybytearray, current, (mybytearray.length-current));
                if(bytesRead >= 0) current += bytesRead;
            } while(bytesRead > -1);

            bos.write(mybytearray, 0 , current);
            bos.flush();
            System.out.println("File " + FILE_TO_RECEIVED + " downloaded (" + current + " bytes read)");*/




        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}