package junxyjunx;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// receive client's request
// get privateKey, encrypt msg and send to client
// receive client's request for CA cert
// send client the cert...
// client uses cert to get publicKey of server and sends encrypted symmetric key over
// use privateKey to decrypt symmetric key
// use symmetric key to send ack to client
// receive encrypted file from client
// decrypt it and print it.

public class CP2Server {
	//Server
	public static ServerSocket sock;
	public static ArrayList<ClientHandlerCP2> clients;
	public static PrivateKey privateKey;
	
	//Input
	public static Scanner in;
	
	public static void main(String[] args){
		int port = 2000;
		clients = new ArrayList<ClientHandlerCP2>();
		
		//Setup PrivateKey
		try{
			privateKey = getPrivateKey("privateKey.der");
			
			sock = new ServerSocket(port);
			//System.out.println("Server up and running");
			
			while(true){
				Socket client = sock.accept();
				//System.out.println("New Client connected");
				ClientHandlerCP2 ch2 = new ClientHandlerCP2(client, privateKey);
				clients.add(ch2);
				ch2.start();
			}
			
		}catch(Exception e){
			//System.out.println(e);
		}
	}
	//Method to extract PrivateKey from .der file
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


class ClientHandlerCP2 extends Thread {
	//Client
	private Socket client;
	private DataInputStream in;
	private DataOutputStream out;

	//Security
	private int nonce;
	private PrivateKey privateKey;
	private SecretKey symmetricKey;
	private Cipher ecipher;
	private Cipher dcipher;
	private Cipher symmEcipher;
	private Cipher symmDcipher;

	//File Save Path
	private String filePath = "C:/Users/Yak Jun Xiang/Desktop";//Change this to fit your computer

	public ClientHandlerCP2(Socket client, PrivateKey key) {
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
			//System.out.println("Connection Error: Unable to connect");
			e.printStackTrace();
		}
	}

	
	
	public void run() {
		long time = System.currentTimeMillis();
		try {
			//Read Request for Identity Proof
			byte[] fromClient1 = receiveMsg(); // Receives request for ID
			//System.out.println("CLIENT>>> " + new String(fromClient1));

			//Send Hello Message (Encrypted)
			byte[] toClient1 = encrypt("Hello, this is SecStore!".getBytes());
			sendMsg(toClient1); 
			//System.out.println("TO CLIENT: " + "Hello, this is SecStore!" + toClient1.length);

			//Read Request for Certificate
			byte[] fromClient2 = receiveMsg(); // Receives Request for Cert
			//System.out.println("CLIENT>>> " + new String(fromClient2));

			//Send Certificate
			File cert = new File("YJX.crt");
			FileInputStream fis = new FileInputStream(cert);
			byte[] certByte = new byte[(int) cert.length()];
			fis.read(certByte);
			sendMsg(certByte); // toClient2
			//System.out.println("Cert sent to Client");
			
			readAndReturnNonce();

			//Receive Symmetric Key (RSA encrypted)
			byte[] fromClient3 = receiveMsg();
			byte[] encodedKey = decrypt(fromClient3);// decrypt key...
			symmetricKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
			//System.out.println("Symmetric Key Received.");
			
			symmEcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			symmEcipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
			symmDcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			symmDcipher.init(Cipher.DECRYPT_MODE, symmetricKey);
			
			// Send confirmation to Client
			String confirmation = "Received Symmetric Key";
			byte[] toClient3 = symmEcipher.doFinal(confirmation.getBytes());
			sendMsg(toClient3);
			//System.out.println("TO CLIENT: " + confirmation);
			
			// Receive fileName (Symmetric Key encrypted)
			byte[] fromClient4 = receiveMsg();
			String fileName = new String(symmDcipher.doFinal(fromClient4));
			//System.out.println("CLIENT>>> " + "FILENAME: " + fileName);
			byte[] toServer4 = "fileName Received".getBytes();
			sendMsg(symmEcipher.doFinal(toServer4));
			//System.out.println("TO CLIENT: " + new String(toServer4));
			
			//Receive and Decrypt file(Symmetric Key encrypted)
			byte[] fromClient5 = receiveMsg();
			byte[] fileByte = symmDcipher.doFinal(fromClient5);
			File savePath = new File(filePath + "/" + fileName);
			FileOutputStream fos = new FileOutputStream(savePath);
			fos.write(fileByte);
			fos.flush();
			fos.close();
			//System.out.println("File received successfully @ " + savePath.getAbsolutePath());
			long timeTaken = System.currentTimeMillis() - time;
			System.out.println("Time Taken in millis: " + String.valueOf(timeTaken));
			//Close connection
			sendMsg("File Received. Closing Connection.".getBytes());
			client.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	

	public byte[] decrypt(byte[] inputByte) throws IllegalBlockSizeException, BadPaddingException {
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

	public byte[] encrypt(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
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

	public byte[] receiveMsg() {
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

	public void sendMsg(byte[] msg) {
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
		//System.out.println("Return Nonce...");
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

