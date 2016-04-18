package junxyjunx;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class APServer {
	//Tools
	public static AP ap;
	public static PublicKey serverKey;
	public static int nonce;

	//Encryption
	public static Cipher ecipher;

	//Socket
	public static Socket server;
	public static DataInputStream in = null;
	public static BufferedReader bin = null;
	public static byte[] input;
	public static OutputStream out = null;

	public static void main(String[] args) {
		String serverIP = "";
		int port = 0;
		try {
			//Create ecipher with PrivateKey

			//ServerSocket
			ServerSocket sock = new ServerSocket(port);
			Socket client = sock.accept();
			in = new DataInputStream(client.getInputStream()); // Byte[] input
			out = client.getOutputStream();

			//Hello this is SecStore

			//Send Certificate

			//
			out.write("Hello SecStore, please prove your identity!".getBytes());
			out.flush();
			in.readFully(input);
			out.write("Give me your certificate signed by CA".getBytes());
			out.flush();
			in.readFully(input);
			ap = new AP(input);
			PublicKey serverKey = ap.getKey();

			//GetNonce
			out.write("!getNonce".getBytes());
			out.flush();
			in.readFully(input);
			nonce = byteArrayToInt(input);

			//Encrypt Message with Nonce & ServerKey
			ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			ecipher.init(Cipher.ENCRYPT_MODE, serverKey);
			String outputMsg = "MyUserName,MyPassword,"+ String.valueOf(nonce);

			//Proceed with Handshake
			out.write(ecipher.doFinal(outputMsg.getBytes()));
			out.flush();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static int byteArrayToInt(byte[] b) 
	{
		int value = 0;
		for (int i = 0; i < 4; i++) {
			int shift = (4 - 1 - i) * 8;
			value += (b[i] & 0x000000FF) << shift;
		}
		return value;
	}

	public static byte[] intToByteArray(int a)
	{
		byte[] ret = new byte[4];
		ret[0] = (byte) (a & 0xFF);   
		ret[1] = (byte) ((a >> 8) & 0xFF);   
		ret[2] = (byte) ((a >> 16) & 0xFF);   
		ret[3] = (byte) ((a >> 24) & 0xFF);
		return ret;
	}
}

class SocketHandler extends Thread {
	private Socket client;
	private DataInputStream in;
	private OutputStream out;

	private byte[] input;
	private byte[] output;

	public SocketHandler (Socket client) {
		this.client = client;
		try {
			in = new DataInputStream(client.getInputStream());
			out = client.getOutputStream();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void run() {
		while (client.isConnected()) {
			try {
				in.readFully(input);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			String inputMsg = input.toString();
			
		}
	}
}


