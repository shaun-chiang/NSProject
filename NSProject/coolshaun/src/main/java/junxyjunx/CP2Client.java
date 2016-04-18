package junxyjunx;

import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.*;

// send request to server
// receive encrypted acknowledgement
// ask server for cert
// receive cert, get public key
// create symmetric key
// encrypt symmetric key with public key
// send encrypted Ks
// receive encrypted acknowledgement from server 
// decrypt with Ks
// encrypt file with Ks and send to server.
// receive confirmation of file transfer.


public class CP2Client {

	public static AP ap;
	public static PublicKey serverKey;
	public static SecretKey symmetricKey;
	
	public static SecureRandom sr;
	public static int nonce;
	
	public static Cipher ecipherPKey;
	public static Cipher dcipherPKey;
	public static Cipher ecipher;
	public static Cipher dcipher;
	
	public static Socket server;
	public static DataInputStream in;
	public static DataOutputStream out;
	public static BufferedReader bin;
	public static byte[] input;
	
	
	public static void main(String[] args){
		//AP
		String path = "SecureFileTransferPRojectrelease.pdf";
		String serverIP = "localhost";
		int port = 2000;
		try{
			Socket server = new Socket(serverIP, port);
			in = new DataInputStream(server.getInputStream());
			bin = new BufferedReader(new InputStreamReader(in));
			out = new DataOutputStream(server.getOutputStream());
			System.out.println("Connected to Server!");
			
			// request and answer from server.
			String toServer1 = "Hello SecStore, please prove your identity!";
			System.out.println("TO SERVER: " + toServer1);
			sendMsg(toServer1.getBytes());
			byte[] fromServer1 = receiveMsg();
			System.out.println("SERVER>>> " + new String(fromServer1));
			
			// request and answer from server
			String toServer2 = "Give me your certificate signed by CA";
			sendMsg(toServer2.getBytes());
			System.out.println("TO SERVER: " + toServer2);
			byte[] fromServer2 = receiveMsg();
			System.out.println("*******************************"); // Start AP
			ap = new AP(fromServer2);
			serverKey = ap.getKey(); // Gets PublicKey
			System.out.println("*******************************"); // End AP
			
			//Setup Decryption with the PublicKey
			dcipherPKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			dcipherPKey.init(Cipher.DECRYPT_MODE, serverKey);
			
			//Setup Encryption with the PublicKey
			ecipherPKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			ecipherPKey.init(Cipher.ENCRYPT_MODE, serverKey);
			
			//Verify message from earlier
			byte[] decryptedinMsg1 = CP1decrypt(fromServer1); // same key as CP1
			System.out.println("DECRYPTED: " + new String(decryptedinMsg1));
			
			verifyNonce();
			
			//END AP
			
			// Create Symmetric Key
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			symmetricKey = keyGen.generateKey();
			
			// Send Symmetric Key to Server
			System.out.println("Sending Symmetric Key to Server");
			byte[] encodedKey = symmetricKey.getEncoded();
			byte[] toServer3 = ecipherPKey.doFinal(encodedKey);//CP1encrypt(encodedKey);
			sendMsg(toServer3);
				
			//Setup Encryption with SymmetricKey
			ecipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			ecipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
			dcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			dcipher.init(Cipher.DECRYPT_MODE, symmetricKey);
			
			// Receive confirmation from Server (received Ks)
			byte[] fromServer3 = receiveMsg();
			System.out.println("SERVER>>> " + new String(dcipher.doFinal(fromServer3)));
			
			//Send File Name
			System.out.println("Sending File");
			File fileToEncrypt = new File(path);
			System.out.println(fileToEncrypt.getAbsolutePath());
			String fileName = fileToEncrypt.getName();
			byte[] toServer4 = ecipher.doFinal(fileName.getBytes());
			sendMsg(toServer4);
			byte[] fromServer4 = receiveMsg();
			System.out.println("SERVER>>> " + new String(dcipher.doFinal(fromServer4))); //Wait for receive Msg
			
			//Encrypt and send file
			FileInputStream fis;
			fis = new FileInputStream(fileToEncrypt);
			byte[] dataByte = new byte[(int) fileToEncrypt.length()];
			fis.read(dataByte);
			byte[] toServer5 = ecipher.doFinal(dataByte);
			sendMsg(toServer5);
			
			//Wait for successful message
			System.out.println("SERVER>>>" + new String(receiveMsg()));
			
		}catch(Exception e){
			System.out.println(e);
		}
		
		
	}
	
	//Methods from CP1
	
	/*
	 * Method to generate Nonce for messages. Used within sendMsg()
	 */
	private static void generateNonce() {
		if (sr == null) {
			sr = new SecureRandom();
		}
		nonce = sr.nextInt();
	}	
	
	public static byte[] receiveMsg() throws SecurityException, IOException { // Receives a message and checks if nonce is correct
		byte[] msg = null;
		int size = in.readInt(); // Gets the size of the message to be sent
		msg = new byte[size]; // Setup buffer to size of message
		in.readFully(msg, 0, size); // Read message from stream
		return msg; // Return message
		
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
	
	public static void sendMsg(byte[] msg) throws Exception { //Sends a message with a new Nonce generated
		int size = msg.length; // Find out size of message
		out.writeInt(size); // Write size of message
		out.write(msg); //Write message
		out.flush(); // FLUSH
	}
	
	public static byte[] CP1decrypt(byte[] inputByte) throws IllegalBlockSizeException, BadPaddingException {
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
				out = dcipherPKey.doFinal(block); //Encrypt the current block
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
	
	public static byte[] CP1encrypt(byte[] input) throws IllegalBlockSizeException, BadPaddingException {
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
				out = ecipherPKey.doFinal(block); // ENCRYPT
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
	
}
