package junxyjunx;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.xml.bind.DatatypeConverter;

/*
 * CP1 Server. Save the privateKey in working directory.Specify save path under ClientHandler.
 */

public class CP1Server {
	//Server
	public static ServerSocket sock;
	public static ArrayList<ClientHandler> clients;
	private static PrivateKey privateKey;

	//Input
	public static Scanner sc;

	public static void main(String[] args) {
		int port = 3000;
		clients = new ArrayList<ClientHandler>();

		//Setup PrivateKey
		try {
			privateKey = getPrivateKey("privateKey.der");

			//Setup Server
			sock = new ServerSocket(port);
			System.out.println("Server up and running");

			while (true) {
				Socket client = sock.accept();
				System.out.println("New Client connected");
				ClientHandler ch = new ClientHandler(client, privateKey);
				clients.add(ch);
				ch.start();
			}
		} catch (Exception e) {
			for (ClientHandler c: clients) {
				c.close();
			}
		}

	}

	//Method to extract PrivateKey from .der file
	private static PrivateKey getPrivateKey(String filename) throws Exception {

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

class ClientHandler extends Thread {
	//Client
	private Socket client;
	private DataInputStream in;
	private DataOutputStream out;

	//Security
	private int nonce;
	private PrivateKey privateKey;
	private Cipher ecipher;
	private Cipher dcipher;

	//File Save Path
	private String filePath = "C:/Users/Yak Jun Xiang/Desktop";//Change this to fit your computer

	public ClientHandler(Socket client, PrivateKey key) {
		this.privateKey = key;
		this.client = client;
		try {
			in = new DataInputStream(client.getInputStream());
			out = new DataOutputStream(client.getOutputStream());

			ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			ecipher.init(Cipher.ENCRYPT_MODE, key);

			dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			dcipher.init(Cipher.DECRYPT_MODE, key);
		} catch (Exception e) {
			System.out.println("Connection Error: Unable to connect");
			e.printStackTrace();
		}
	}

	public void run() {
		long time = System.currentTimeMillis();
		try {
			//Read Request for Identity Proof
			byte[] inMsg1 = receiveMsg(); // Receives request for ID
			System.out.println("CLIENT>>> " + new String(inMsg1));

			//Send Hello Message (Encrypted)
			byte[] outMsg1 = encrypt("Hello, this is SecStore!".getBytes());
			sendMsg(outMsg1); 
			System.out.println("TO CLIENT: " + "Hello, this is SecStore!");

			//Read Request for Certificate
			byte[] inMsg2 = receiveMsg(); // Receives Request for Cert
			System.out.println("CLIENT>>> " + new String(inMsg2));

			//Send Certificate
			File cert = new File("YJX.crt");
			FileInputStream fis = new FileInputStream(cert);
			byte[] certByte = new byte[(int) cert.length()];
			fis.read(certByte);
			sendMsg(certByte);
			//System.out.println("Cert sent to Client");
			
			readAndReturnNonce();

			//Receive fileName (RSA encrypted)
			byte[] inMsg3 = receiveMsg();
			String fileName = new String(decrypt(inMsg3));
			System.out.println("CLIENT>>> " + "FILENAME: " + fileName);
			byte[] outMsg3 = "fileName Received".getBytes();
			sendMsg(encrypt(outMsg3));
			System.out.println("TO CLIENT: " + new String(outMsg3));

			//Receive and Decrypt file(RSA encrypted)
			byte[] inMsg4 = receiveMsg();
			byte[] fileByte = decrypt(inMsg4);
			File savePath = new File(filePath + "/" + fileName);
			FileOutputStream fos = new FileOutputStream(savePath);
			fos.write(fileByte);
			fos.flush();
			fos.close();
			System.out.println("File received successfully @ " + savePath.getAbsolutePath());
			
			long timeTaken = System.currentTimeMillis() - time;
			//Close connection
			System.out.println("Time Taken in millis: " + String.valueOf(timeTaken));
			sendMsg("File Received. Closing Connection.".getBytes());
			client.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private byte[] decrypt(byte[] inputByte) throws IllegalBlockSizeException, BadPaddingException {
		int blockSize = 128;
		int pointer = 0;
		byte[] block;
		ArrayList<Byte> output = new ArrayList<Byte>();

		while (pointer != inputByte.length) {
			byte[] out = null;
			if (pointer + blockSize >= inputByte.length) { //If reach end of dataByte (block < 128 bytes)
				block = Arrays.copyOfRange(inputByte, pointer, inputByte.length);
				pointer = inputByte.length;
			} else { //Processing dataByte (block = 128 bytes)
				block = Arrays.copyOfRange(inputByte, pointer, pointer + blockSize);
				pointer += blockSize;
			}
			try {
				out = dcipher.doFinal(block);
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} //Encrypt the current block

			for (byte b: out) {
				output.add(b); // Add to output arrayList
			}
		}
		Byte[] decrypted = new Byte[output.size()];
		output.toArray(decrypted);
		byte[] outByte = new byte[decrypted.length];
		for (int i = 0; i < decrypted.length;i++) {
			outByte[i] = decrypted[i];
		}
		return outByte;
	}

	private byte[] encrypt(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
		int blockSize = 117;
		int pointer = 0;
		byte[] block;
		ArrayList<Byte> output = new ArrayList<Byte>();

		while (pointer != input.length) {
			byte[] out = null;
			if (pointer + 117 > input.length) { //If reach end of dataByte (block < 117 bytes)
				block = Arrays.copyOfRange(input, pointer, input.length);
				pointer = input.length;
			} else { //Processing dataByte (block = 117 bytes)
				block = Arrays.copyOfRange(input, pointer, pointer + 117);
				pointer += 117;
			}
			out = ecipher.doFinal(block);//Encrypt the current block
			for (byte b: out) {
				output.add(b); // Add to output arrayList
			}
		}
		Byte[] encrypted = new Byte[output.size()];
		output.toArray(encrypted);
		byte[] outByte = new byte[encrypted.length];
		for (int i = 0; i < encrypted.length;i++) {
			outByte[i] = encrypted[i];
		}
		return outByte;

	}

	private byte[] receiveMsg() {
		byte[] msg = null;
		try {
			int size = in.readInt();
			msg = new byte[size];
			in.readFully(msg, 0 , size);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return msg;

	}

	private void sendMsg(byte[] msg) {
		int size = msg.length;
		try {
			out.writeInt(size);
			out.write(msg);
			out.flush();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void readAndReturnNonce() {
		byte[] nonce = new byte[4];
		try {
			in.readFully(nonce);
			byte[] encryptedNonce = encrypt(nonce);
			out.write(encryptedNonce);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		System.out.println("Return Nonce...");
	}

	public void close() {
		try {
			client.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}

