package ryany;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

/**
 * Created by Nayr on 13/4/2016.
 */
public class SecStoreRyan {

    public static String filePath = "D:\\Documents\\NSProject\\NSProject\\ns_project\\";

    public static void main(String[] args) {
        try {
            //Retrieving the Server private and public key
            SecStoreRyan Secstore = new SecStoreRyan();
            PublicKey publicKey = Secstore.getPublicKey(filePath+"publicServer.der");
            PrivateKey privateKey = Secstore.getPrivateKey(filePath+"privateServer.der");

            //Initialise port and wait for client connection
            ServerSocket serverSocket = new ServerSocket(4321);
            System.out.println("-------------------Waiting For Client-------------------");
            Socket newSocket = serverSocket.accept();
            System.out.println("--------------------Client Connected--------------------");

            //Input and Output channels
            DataOutputStream out = new DataOutputStream(newSocket.getOutputStream());
            DataInputStream in = new DataInputStream(newSocket.getInputStream());

            // Receiving nounce from client and encrypt'
            int len = in.readInt();
            byte[] clientNounce = new byte[len];
            in.read(clientNounce, 0, len);
            Cipher ecipher = Cipher.getInstance("RSA");
            ecipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedBytes = ecipher.doFinal(clientNounce);
            System.out.println("nounce received");

            // Send encrypted nounce back
            out.writeInt(encryptedBytes.length);
            out.write(encryptedBytes);
            out.flush();
            System.out.println("nounce sent");

            //Sending of Signed Certificate to client
/*            File myFile = new File ("Signed Certificate - 1000985.crt");
            byte [] bytearray  = new byte [(int)myFile.length()];
            FileInputStream fis = new FileInputStream(myFile);
            BufferedInputStream bis = new BufferedInputStream(fis);
            bis.read(bytearray, 0, bytearray.length);
            OutputStream outfile = newSocket.getOutputStream();
            System.out.println("Sending " + "Signed Certificate - 1000985.crt" + "(" + bytearray.length + " bytes)");
            outfile.write(bytearray,0,bytearray.length);
            outfile.flush();*/

            File cert = new File(filePath+"shaun_chiang.crt");
            FileInputStream fis = new FileInputStream(cert);
            byte[] certByte = new byte[(int) cert.length()];
            fis.read(certByte);
            out.writeInt(certByte.length);
            out.write(certByte);

            in.close();
            out.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //Retrieving of key from .der format
    public PublicKey getPublicKey(String filename) throws Exception{
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)file.length()];
        dis.readFully(keyBytes);
        dis.close();

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    //Retrieving of key from .der format
    public PrivateKey getPrivateKey(String filename) throws Exception{
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)file.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

}
