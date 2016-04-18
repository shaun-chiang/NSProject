package junxyjunx;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;


public class KeyTest {
	public static AP ap;
	public static PublicKey publicKey;
	private static PrivateKey privateKey;
	
public static void main(String[] args) {
	try {
		privateKey = getPrivateKey("privateKey.der");
		File cert = new File("YJX.crt");
		FileInputStream  fis = new FileInputStream (cert);
		byte[] certByte = new byte[(int) cert.length()];
		fis.read(certByte);
		AP ap = new AP(certByte);
		publicKey = ap.getKey();
		
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.ENCRYPT_MODE, publicKey);

		String test = "HelloWorld";
		byte[] testByte = test.getBytes();
		System.out.println("Message Size: " + testByte.length);
		byte[] publicE = c.doFinal(testByte);
		System.out.println("Encryption done");
		System.out.println("Encryption Size: " + publicE.length);
		
		c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.DECRYPT_MODE, privateKey);
		
		byte[] privateD = c.doFinal(publicE);
		System.out.println("Decryption Size: " + privateD.length);
		System.out.println(new String(privateD));
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
}

public static PrivateKey getPrivateKey(String filename) throws Exception {

    File f = new File(filename);
    FileInputStream fis = new FileInputStream(f);
    DataInputStream dis = new DataInputStream(fis);
    byte[] keyBytes = new byte[(int) f.length()];
    dis.readFully(keyBytes);
    dis.close();

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
}
}
