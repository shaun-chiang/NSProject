package junxyjunx;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
/*
 * CP1 Client. Client initiates connection and starts talking.
 * receiveMsg() - reads the inputstream and checks if nonce is correct. Returns the message in byte[]
 * sendMsg(byte[] b) - attaches a new nonce to the msg and sends a premessage indicating the size of the msg.
 * encrypt(byte[] b) - Encrypts the given byte[] and returns a byte[]
 * decrypt(byte[] b) - Decrypts the given byte[] and returns a byte[]
 * 
 * To read a plaintext message, use new String(byte[] b).
 */

public class CP1Client {
	//Tools
	public static AP ap;
	public static PublicKey serverKey;
	public static SecureRandom sr = null;
	public static int nonce;
	
	//Encryption
	public static Cipher ecipher;
	
	//
	public static Cipher dcipher;
	
	//Socket
	public static Socket server;
	public static DataInputStream in = null;
	public static BufferedReader bin = null;
	public static byte[] input;
	public static DataOutputStream out = null;
	
	public static void main(String[] args) {
		//AP
		String path = "SecureFileTransferProjectRelease.pdf";
		String serverIP = "127.0.0.1";
		int port = 3000;
		try {
			//Socket setup
			Socket server = new Socket(serverIP, port);
			in = new DataInputStream(server.getInputStream()); // Byte[] input
			bin = new BufferedReader(new InputStreamReader(in));
			out = new DataOutputStream(server.getOutputStream());
			System.out.println("Connected to Server!");
			
			//Request for verification
			String outMsg1 = "Hello SecStore, please prove your identity!";
			System.out.println("TO SERVER: " + outMsg1);
			sendMsg(outMsg1.getBytes());	//Sends the msg
			byte[] inMsg1 = receiveMsg(); //Receives the msg
			System.out.println("SERVER>>> " + new String(inMsg1)); // prints encrypted message
			
			//Ask for Cert
			String outMsg2 = "Give me your certificate signed by CA";
			sendMsg(outMsg2.getBytes());
			System.out.println("TO SERVER: " + outMsg2);
			byte[] inMsg2 = receiveMsg(); // Receives Cert
			System.out.println("*******************************"); // Start AP
			ap = new AP(inMsg2);
			PublicKey serverKey = ap.getKey(); // Gets PublicKey
			System.out.println("*******************************"); // End AP
			
			//Setup Decryption with the PublicKey
			dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			dcipher.init(Cipher.DECRYPT_MODE, serverKey);
			
			//Verify message from earlier
			byte[] decryptedinMsg1 = CP1decrypt(inMsg1);
			System.out.println("DECRYPTED: " + new String(decryptedinMsg1));
			
			//Establish Session Nonce
			verifyNonce();
			System.out.println("Server is verified");
			//END AP
			
			//CP1
			
			//Setup Encryption with PublicKey
			ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			ecipher.init(Cipher.ENCRYPT_MODE, serverKey);
			
			//Send File Name
			System.out.println("Sending File");
			File fileToEncrypt = new File(path);
			System.out.println(fileToEncrypt.getAbsolutePath());
			String fileName = fileToEncrypt.getName();
			byte[] outMsg3 = CP1encrypt(fileName.getBytes());
			sendMsg(outMsg3); // Send over file name
			byte[] inMsg3 = receiveMsg();
			System.out.println("SERVER>>> " + new String(CP1decrypt(inMsg3))); //Wait for receive Msg
			
			//Encrypt File for transfer
			FileInputStream fis;
			fis = new FileInputStream(fileToEncrypt);
			byte[] dataByte = new byte[(int) fileToEncrypt.length()];
			fis.read(dataByte);
			byte[] outMsg4 = CP1encrypt(dataByte);
			sendMsg(outMsg4);
			
			//Wait for successful message
			System.out.println(new String(receiveMsg()));
	
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} 
		
	}
	
	/*
	 * Method to generate Nonce for messages. Used within sendMsg()
	 */
	private static void generateNonce() {
		if (sr == null) {
			sr = new SecureRandom();
		}
		nonce = sr.nextInt();
	}
	
	private static void verifyNonce() throws SecurityException, IOException, IllegalBlockSizeException, BadPaddingException {
		generateNonce();
		out.writeInt(nonce);
		out.flush();
		byte[] encryptedNonce = new byte[128];
		in.readFully(encryptedNonce);
		byte[] decryptedNonce = CP1decrypt(encryptedNonce);
		int returnNonce = ((decryptedNonce[0] & 0xFF) << 24) | ((decryptedNonce[1] & 0xFF) << 16) | ((decryptedNonce[2] & 0xFF) << 8) | (decryptedNonce[3] & 0xFF);
		if (returnNonce != nonce) {
			throw new SecurityException ("Invalid Nonce");
		}
	}
	
	private static byte[] receiveMsg() throws SecurityException, IOException { // Receives a message and checks if nonce is correct
		byte[] msg = null;
		int size = in.readInt(); // Gets the size of the message to be sent
		msg = new byte[size]; // Setup buffer to size of message
		in.readFully(msg, 0, size); // Read message from stream
		return msg; // Return message
		
	}
	
	private static void sendMsg(byte[] msg) throws Exception { //Sends a message with a new Nonce generated
		int size = msg.length; // Find out size of message
		out.writeInt(size); // Write size of message
		out.write(msg); //Write message
		out.flush(); // FLUSH
	}
	
	private static byte[] CP1encrypt(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
		int blockSize = 117; // RSA key of 1024 size can only encode blocks of 117 without padding. Padding takes up 11 bytes, giving us a packet size of 128 bytes.
		int pointer = 0;	 // Pointer
		byte[] block;		 // Working block
		ArrayList<Byte> output = new ArrayList<Byte>(); //ArrayList to store encrypted bytes

		
		while (pointer != input.length) {
			byte[] out = null;
			if (pointer + 117 >= input.length) { //If reach end of dataByte (block < 117 bytes)
				block = Arrays.copyOfRange(input, pointer, input.length);
				pointer = input.length;
			} else { //Processing data (block = 117 bytes)
				block = Arrays.copyOfRange(input, pointer, pointer + 117);
				pointer += 117;
			}
				out = ecipher.doFinal(block); // ENCRYPT
			for (byte b: out) {
				output.add(b); // Add to output arrayList
			}
		}
		//Changing from ArrayList to byte[]
		Byte[] encrypted = new Byte[output.size()];
		output.toArray(encrypted);
		byte[] outByte = new byte[encrypted.length];
		for (int i = 0; i < encrypted.length;i++) {
			outByte[i] = encrypted[i];
		}
	return outByte;
	}
	
	private static byte[] CP1decrypt(byte[] inputByte) throws IllegalBlockSizeException, BadPaddingException {
		int blockSize = 128; //For decryption, we decrypt block by block inclusive of padding.
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
				out = dcipher.doFinal(block); //Encrypt the current block
			for (byte b: out) {
				output.add(b); // Add to output arrayList
			}
		}
		//Changing from ArrayList to byte[]
		Byte[] decrypted = new Byte[output.size()];
		output.toArray(decrypted);
		byte[] outByte = new byte[decrypted.length];
		for (int i = 0; i < decrypted.length;i++) {
			outByte[i] = decrypted[i];
		}
		return outByte;
	}
}


