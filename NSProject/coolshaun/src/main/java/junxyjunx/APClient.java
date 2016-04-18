package junxyjunx;

import java.io.BufferedReader;
import java.io.DataInputStream;
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


public class APClient {
	//Tools
	public static AP ap;
	public static PublicKey serverKey;
	public static SecureRandom sr = null;
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
		//AP
		String path = "filepath";
		String serverIP = "";
		int port = 0;
		try {
			Socket server = new Socket(serverIP, port);
			in = new DataInputStream(server.getInputStream()); // Byte[] input
			bin = new BufferedReader(new InputStreamReader(in));
			out = server.getOutputStream();
			
			//Getting ServerKey
			nonce = generateNonce();
			String outMsg = "Hello SecStore, please prove your identity!:" + String.valueOf(nonce);
			out.write(outMsg.getBytes());
			out.flush();
			System.out.println(readMsg());
				
			out.write("Give me your certificate signed by CA".getBytes());
			out.flush();
			in.readFully(input);
			ap = new AP(input);
			PublicKey serverKey = ap.getKey();
			
			//END AP
			
			//CP1
			//Encrypt File for transfer
			ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			ecipher.init(Cipher.ENCRYPT_MODE, serverKey);
			
			File fileToEncrypt = new File(path);
			System.out.println(fileToEncrypt.getAbsolutePath());
			FileInputStream fis;
			fis = new FileInputStream(fileToEncrypt);
			byte[] dataByte = new byte[(int) fileToEncrypt.length()];
			fis.read(dataByte);
			
			int blockSize = 117;
			int pointer = 0;
			byte[] block;
			ArrayList<Byte> output = new ArrayList<Byte>();
			Byte[] encrypted;
			while (pointer != dataByte.length) {
				if (pointer + 117 > dataByte.length) { //If reach end of dataByte (block < 117 bytes)
					block = Arrays.copyOfRange(dataByte, pointer, dataByte.length);
					pointer = dataByte.length;
				} else { //Processing dataByte (block = 117 bytes)
					block = Arrays.copyOfRange(dataByte, pointer, pointer + 117);
					pointer += 117;
				}
				byte[] out = ecipher.update(block); //Encrypt the current block
				for (byte b: out) {
					output.add(b); // Add to output arrayList
				}
			}
//			output.toArray(encrypted);
			
//			out.write(encrypted);
			out.flush();

			
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				server.close();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		
	}
	
	public static int generateNonce() {
		if (sr == null) {
			sr = new SecureRandom();
		}
		return sr.nextInt();
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
	
	public static String readMsg() throws SecurityException, IOException {
		in.readFully(input);
		String inputStr = input.toString();
		String[] stringSplit = inputStr.split(":");
		int Snonce = Integer.parseInt(stringSplit[stringSplit.length - 1]);
		if(nonce != Snonce) {
			throw new SecurityException("Invalid Nonce");
		} else {
			return stringSplit[0];
		}
	}

}


