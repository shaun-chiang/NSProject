package junxyjunx;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/*
 * Authentication Protocol
 * This program asks for a certificate and runs a verification against the CA cert in the program.
 * TODO: There is a problem with AP. We need to find it and fix it.
 */

public class AP {
	//Tools
	public CertificateFactory cf; // This generates certificate Object from file
	public Scanner sc;			 // Scanner to receive input
	//CA Cert 
	public InputStream certInput; // The fileStream which contains the Certificate file
	public X509Certificate cert;	 // The Certificate Object generated from the file
	public PublicKey CAkey;		 // The Public Key generated from the Object

	//Cert in Question
	public X509Certificate ServerCert;	//The Certificate we want to test
	public PublicKey serverKey;

	public AP(byte[] serverByte) throws Exception {

			certInput = new FileInputStream("CA.crt");
			cf = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) cf.generateCertificate(certInput);
			CAkey = cert.getPublicKey();
			sc = new Scanner(System.in);


			System.out.println("Processing your Certificate...");
			ServerCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(serverByte));
			ServerCert.checkValidity(); //Check if cert is valid for time
			ServerCert.verify(CAkey); // Verify cert with CAkey
			serverKey = ServerCert.getPublicKey(); //Once cert is verified, extract PublicKey

			//Successful verification
			System.out.println("Your Certificate is successfully verified!");

		System.out.println("This is the end of AP.");
	}

	public PublicKey getKey() {
		return serverKey;
	}
	
}
