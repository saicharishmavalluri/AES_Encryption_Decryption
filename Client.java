import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

public class Client {
	public static void main(String[] args) {
		// provide the arguments
		c_Provide_inputs inputs = new c_Provide_inputs();
		String ipAddr = inputs.GetIpAddr();
		int port = inputs.GetPort();
		String serverPubKey = inputs.GetServerPublicKey();
		String clientPvtKey = inputs.GetClientPrivateKey();
		
		// Encrypt AES key with signature
		Encrypter aesEncrypter = new Encrypter(serverPubKey);
		SecretKey aesKey = aesEncrypter.GetAesRandomKey();
		byte[] encryptedKey = aesEncrypter.GetEncryptedAESKey();
		byte[] encryptedKeyWithSign = c_Digi_sign.GetDigitalSignEncryptedKey(encryptedKey, clientPvtKey);
	
		// create Socket and make Connection
		c_SocketConnection sc = new c_SocketConnection(ipAddr, port);
		//sends AES key with signature to server
		sc.SendDataToServer(encryptedKeyWithSign);

		//receives AES key signature from server and validates
		byte[] aesKeywithSign = (byte[])sc.GetDataFromServer();
		boolean signatureVerified = c_Digi_sign.VerifySignature(aesKeywithSign, serverPubKey);
		if(signatureVerified == true){
			System.out.println("Signature of AES key matches\n");
			// get plaintext that need to be sent to server
			String textString = inputs.GetTexString();
			byte[] textByte = textString.getBytes();

			//text length in unit of bytes
			Integer textStringLength = textByte.length;
			
			//text signature
			byte[] textWithSign = c_text_Digi_sign.GetDigitalSignPlainText(textByte, clientPvtKey);

			//ciphertext
			textEncrypter textEncrypt = new textEncrypter(aesKey);
			String cipherText = textEncrypt.GetEncryptedText(textString);
			
			//send data to server
			sc.SendDataToServer(textStringLength);
			sc.SendDataToServer(textWithSign);
			sc.SendDataToServer(cipherText);
			
			//receive signature of text from server and verifies it
			byte[] textSign = (byte[])sc.GetDataFromServer();
			boolean textverif = c_text_Digi_sign.VerifySignature(textSign, textString.getBytes(), serverPubKey);
			if(textverif == true){
				System.out.println("Signature of text matches\n");
				sc.c_CloseSocket();
				return;
			}
			else{
				System.out.println("Signature of text doesn't match\n");
				sc.c_CloseSocket();
				return;
			}
		}
		else{
			System.out.println("Signature of AES key doesn't match\n");
			sc.c_CloseSocket();
			return;
		}
		
	}
}


class c_text_Digi_sign
{
	public c_text_Digi_sign() {
		
	}
	
	public static byte[] GetDigitalSignPlainText(byte[] textByte, String clientPvtKeyFile)
	{	
		byte[] signature = null;
		PrivateKey clientPvtKey = c_KeyFileReader.GetPrivateKeyFromFile(clientPvtKeyFile);
				
		try {
		
			Signature sign = Signature.getInstance("SHA512withRSA");
			sign.initSign(clientPvtKey);
			sign.update(textByte);
			signature = sign.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		return signature;
	}
	
	public static boolean VerifySignature(byte[] signature, byte[] decrText, String serPubKeyFile)
	{
		PublicKey servPubKey = c_KeyFileReader.GetPublicKeyFromFile(serPubKeyFile);
		boolean verified = false;		
		try {
			Signature sign = Signature.getInstance("SHA512withRSA");
			sign.initVerify(servPubKey);
			sign.update(decrText);
			verified = sign.verify(signature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		return verified;
	}
}

class c_Digi_sign
{
	public c_Digi_sign() {
		
	}
	
	public static byte[] GetDigitalSignEncryptedKey(byte[] aesEncryptedKey, String clientPvtKeyFile)
	{	
		
		PrivateKey clientPvtKey = c_KeyFileReader.GetPrivateKeyFromFile(clientPvtKeyFile);
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();		
		try {
			byteStream.write(aesEncryptedKey);
			Signature sign = Signature.getInstance("SHA512withRSA");
			sign.initSign(clientPvtKey);
			sign.update(aesEncryptedKey);
			byteStream.write(sign.sign());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		
		return byteStream.toByteArray();
	}
	private static byte[] GetEncryptedKey(byte[] aesEncryptedKey)
	{
		return Arrays.copyOfRange(aesEncryptedKey, 0, 256);
	}
	
	private static byte[] GetSignature(byte[] aesEncryptedKey)
	{
		return Arrays.copyOfRange(aesEncryptedKey, 256, aesEncryptedKey.length);
	}
	
	public static boolean VerifySignature(byte[] aesEncryptedKey, String serverPubKeyFile)
	{
		PublicKey serverPubKey = c_KeyFileReader.GetPublicKeyFromFile(serverPubKeyFile);
		boolean verified = false;		
		try {
			Signature sign = Signature.getInstance("SHA512withRSA");
			sign.initVerify(serverPubKey);
			sign.update(GetEncryptedKey(aesEncryptedKey));
			verified = sign.verify(GetSignature(aesEncryptedKey));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		return verified;
	}
}

class FileDecrypter
{
	private SecretKey aesKeyData = null;
	private IvParameterSpec ivSpec = null;
	private byte[] fileData = null;
	PublicKey serverPubKey = null;
	
	public FileDecrypter(byte[] encryptedContents, String serverPubKeyFile, SecretKey aesKey)
	{
		serverPubKey = c_KeyFileReader.GetPublicKeyFromFile(serverPubKeyFile);	
		aesKeyData = aesKey;
		ivSpec = new IvParameterSpec(GetIv(encryptedContents));
		fileData = GetFileContents(encryptedContents);
	}

	private byte[] GetIv(byte[] encryptedContents)
	{
		return Arrays.copyOfRange(encryptedContents, 0, 16);
	}
	
	private byte[] GetFileContents(byte[] encryptedContents)
	{
		return Arrays.copyOfRange(encryptedContents, 16, encryptedContents.length);
	}
	
	
	private void DecryptFileContents(Cipher ci, InputStream in, ByteArrayOutputStream out)
	{
	    byte[] ibuf = new byte[1024];
	    int len;
	    try {
			while ((len = in.read(ibuf)) != -1) 
			{
			    byte[] obuf = ci.update(ibuf, 0, len);
			    if ( obuf != null ) 
			    	out.write(obuf);
			}
			byte[] obuf = ci.doFinal();
			if ( obuf != null ) 
				out.write(obuf);
	    }catch (IOException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	    
	}
	
	public byte[] GetDecryptedFileContents()
	{
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		InputStream in = new ByteArrayInputStream(fileData);
		try {
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, aesKeyData, ivSpec);
			DecryptFileContents(ci, in, byteStream);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return byteStream.toByteArray();
	}
}

class Encrypter
{
	
	PublicKey serverPubKey = null;
	SecretKey aesRandKey = null;
	
	public Encrypter(String serverPubKeyFile) {
		serverPubKey = c_KeyFileReader.GetPublicKeyFromFile(serverPubKeyFile);
		aesRandKey = GenerateAESRandomKey();
	}
	
	public SecretKey GetAesRandomKey()
	{
		
		return aesRandKey;
	}
	
	private SecretKey GenerateAESRandomKey()
	{
		SecretKey key = null;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return key;
	}
	
	private byte[] EncryptKeyWithPublicKey()
	{
		byte[] key = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
			key = cipher.doFinal(aesRandKey.getEncoded());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} 
		
		return key;
	}
	
	public byte[] GetEncryptedAESKey()
	{
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		try {
			byteStream.write(EncryptKeyWithPublicKey());
		} catch (IOException e) {
			e.printStackTrace();
		}
		return byteStream.toByteArray();
	}
}

class textEncrypter{
	private SecretKey aesSecKey = null;
	public textEncrypter(SecretKey key) {
		aesSecKey = key;
	}
	
	private byte[] GenerateIv()
	{
		byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		return iv;
	}
	
	public String GetEncryptedText(String textString)
	{
		String cipherText = null;
		byte[] iV = GenerateIv();
		IvParameterSpec ivSpec = new IvParameterSpec(iV);
		try {
			
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.ENCRYPT_MODE, aesSecKey, ivSpec);
			cipherText = Base64.getEncoder().encodeToString(ci.doFinal(textString.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return cipherText;
	}


}


class c_KeyFileReader
{
	public c_KeyFileReader() {
	}
	
	public static PublicKey GetPublicKeyFromFile(String filePath)
	{
		PublicKey pubKey = null;
		try
		{
			byte[] bytes = Files.readAllBytes(Paths.get(filePath));
			X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			pubKey = kf.generatePublic(ks);
		}
		catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	    return pubKey;
	}
	
	public static PrivateKey GetPrivateKeyFromFile(String filePath)
	{
		PrivateKey pvtKey = null;
		try
		{
			byte[] bytes = Files.readAllBytes(Paths.get(filePath));
		    PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    pvtKey = kf.generatePrivate(ks);
		}
		catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	    return pvtKey;
	}
}


class c_Provide_inputs
{
	private Scanner s;
	public c_Provide_inputs() {
		s = new Scanner(System.in);
	}
	
	public String GetIpAddr()
	{
		System.out.println("Enter Server_IP");
		String ipAddr = s.nextLine();
		return ipAddr;
	}
	
	public int GetPort()
	{
		System.out.println("Enter Server Port Number");
		String port = s.nextLine();
		return Integer.parseInt(port);
	}
	
	public String GetClientPrivateKey()
	{
		System.out.println("Enter Client Private file location");
		String pvtKeyFile = s.nextLine();
		return pvtKeyFile;
	}
	
	public String GetServerPublicKey()
	{
		System.out.println("Enter Server public file location");
		String pubKeyFile = s.nextLine();
		return pubKeyFile;
	}
	public String GetTexString()
	{
		System.out.println("Enter the string:");
		String textString = s.nextLine();
		return textString;
	}
}

class c_SocketConnection
{
	String ipAddr;
	int port;
	Socket socket;
	DataOutputStream outStream;
	
	public c_SocketConnection(String ipAddr, int port) {
		c_CreateSocket(ipAddr, port);
	}
	
	private void c_CreateSocket(String ipAddr, int port) {
		try {
			socket = new Socket(ipAddr, port);
			
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}		
	}

	public void c_CloseSocket()
	{
		try {
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}	
	}
	
	public void SendDataToServer(Object data)
	{
		try {
			ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
			outStream.writeObject(data);
			outStream.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public Object GetDataFromServer()
	{
		Object data = null;
		try {
			ObjectInputStream output = new ObjectInputStream(socket.getInputStream()); 
			data = output.readObject();
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		return data;
	}
}
