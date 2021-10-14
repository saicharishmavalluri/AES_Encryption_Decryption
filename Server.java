import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.ServerSocket;
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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.KeyGenerator;
///Users/jnanadeepputta/Desktop/ISU/COMS559/assignment3
public class Server {
	public static void main(String[] args) {
		// provide the arguments
		s_Provide_inputs inputs = new s_Provide_inputs();
		int port = inputs.GetPort();
		
		// Socket
		s_SocketConnection sc = new s_SocketConnection(port);
		
		// Get encrypted Keys from client
		byte[] data = (byte[])sc.GetDataFromClient();
		
		// Validate Signature
		String clientPubKey = inputs.GetClientPublicKey();
		boolean signatureVerified = s_Digi_Sign.VerifySignature(data, clientPubKey);
		if(signatureVerified == true)
		{
			System.out.println("Signature of AES key matches\n");
			
			//Decrypt AES key.
			String serverPvtKey = inputs.GetServerPrivateKey();
			KeyDecrypter decrypter = new KeyDecrypter(serverPvtKey);
			SecretKey aesKey = decrypter.GetDecryptedKey(data);
			
			
			//AES key with encryption 
			KeyEncrypter aesEncrypter = new KeyEncrypter(clientPubKey);
			byte[] encryptedKey = aesEncrypter.GetEncryptedAESKey(aesKey);
			byte[] aesKeyWithSign = s_Digi_Sign.GetDigitalSignEncryptedKey(encryptedKey, serverPvtKey);
			sc.SendDataToClient(aesKeyWithSign);

			//text and its information from client
			int length = (int)sc.GetDataFromClient();
			byte[] textSign = (byte[])sc.GetDataFromClient();
			String ciphertext = (String)sc.GetDataFromClient();
			
			// Decrypt File contents.
			textDecrypter fileDecypter = new textDecrypter(ciphertext, clientPubKey, aesKey);
			String decryptedFileContent = fileDecypter.GetDecryptedFileContents();
			System.out.println("text received : "+decryptedFileContent+"\n");

			//string signature verification
			boolean verification = s_text_Digi_sign.VerifySignature(textSign, decryptedFileContent.getBytes(), clientPubKey);
			if(verification == true){
				System.out.println("Signature of text matches\n");

				//sends signature of string to client
				byte[] stringSign = s_text_Digi_sign.GetDigitalSignPlainText(decryptedFileContent.getBytes(), serverPvtKey);
				sc.SendDataToClient(stringSign);
				sc.CloseSocket();
			}
			else{
				System.out.println("Signature of text doesn't match\n");
				sc.CloseSocket();
				return;
			}
		}
		else
		{
			System.out.println("Signature of AES key doesn't match\n");
			sc.CloseSocket();
			return;
		}
		
		
	}
}
class s_text_Digi_sign
{
	public s_text_Digi_sign() {
		
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
	
	public static boolean VerifySignature(byte[] signature, byte[] decrText, String clientPubKeyFile)
	{
		PublicKey clientPubKey = c_KeyFileReader.GetPublicKeyFromFile(clientPubKeyFile);
		boolean verified = false;		
		try {
			Signature sign = Signature.getInstance("SHA512withRSA");
			sign.initVerify(clientPubKey);
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
class textDecrypter
{
	private SecretKey aesKeyData = null;
	private IvParameterSpec ivSpec = null;
	private String fileData = null;
	private String ecnrText = null;
	PublicKey serverPubKey = null;
	
	public textDecrypter(String cipherText, String serverPubKeyFile, SecretKey aesKey)
	{
		serverPubKey = s_KeyFileReader.GetPublicKeyFromFile(serverPubKeyFile);	
		aesKeyData = aesKey;
		byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		ivSpec = new IvParameterSpec(iv);
		fileData = cipherText;
		
	}
	
	public String GetDecryptedFileContents()
	{	
	
		try {
			Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
			ci.init(Cipher.DECRYPT_MODE, aesKeyData, ivSpec);
			ecnrText = new String(ci.doFinal(Base64.getDecoder().decode(fileData)));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return ecnrText;
	}
}

class KeyEncrypter
{
	
	PublicKey serverPubKey = null;
	SecretKey aesRandKey = null;
	
	public KeyEncrypter(String serverPubKeyFile) {
		serverPubKey = s_KeyFileReader.GetPublicKeyFromFile(serverPubKeyFile);
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
			keyGen.init(128);
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return key;
	}
	private byte[] EncryptKeyWithPublicKey(SecretKey aesKey)
	{
		byte[] key = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
			key = cipher.doFinal(aesKey.getEncoded());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} 
		
		return key;
	}
	
	public byte[] GetEncryptedAESKey(SecretKey aesKey)
	{
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		try {
			byteStream.write(EncryptKeyWithPublicKey(aesKey));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return byteStream.toByteArray();
	}
}

class KeyDecrypter
{
	PrivateKey serverPvtKey = null;
	public KeyDecrypter(String serverPvtKeyFile) {
		serverPvtKey = s_KeyFileReader.GetPrivateKeyFromFile(serverPvtKeyFile);
	}
	
	private byte[] GetEncryptedKey(byte[] aesEncryptedKey)
	{
		return Arrays.copyOfRange(aesEncryptedKey, 0, 256);
	}
	
	public SecretKey GetDecryptedKey(byte[] aesEncryptedKey)
	{
		SecretKey secKey = null;
		try {
			byte[] keyWithoutSignature = GetEncryptedKey(aesEncryptedKey);
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, serverPvtKey);
			byte[] key = cipher.doFinal(keyWithoutSignature);
			secKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return secKey;
	}
}


class s_Digi_Sign
{
	public s_Digi_Sign() {
		
	}
	public static byte[] GetDigitalSignEncryptedKey(byte[] aesEncryptedKey, String serverPvtKeyFile)
	{
		PrivateKey serverPvtKey = s_KeyFileReader.GetPrivateKeyFromFile(serverPvtKeyFile);
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();		
		try {
			byteStream.write(aesEncryptedKey);
			Signature sign = Signature.getInstance("SHA512withRSA");
			sign.initSign(serverPvtKey);
			sign.update(aesEncryptedKey);
			byteStream.write(sign.sign());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (IOException e) {
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
	
	public static boolean VerifySignature(byte[] aesEncryptedKey, String clientPubKeyFile)
	{
		PublicKey clientPubKey = s_KeyFileReader.GetPublicKeyFromFile(clientPubKeyFile);
		boolean verified = false;		
		try {
			Signature sign = Signature.getInstance("SHA512withRSA");
			sign.initVerify(clientPubKey);
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

class s_KeyFileReader
{
	public s_KeyFileReader() {
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

class s_Provide_inputs
{
	private Scanner s;
	public s_Provide_inputs() {
		s = new Scanner(System.in);
	}
		
	public int GetPort()
	{
		System.out.println("Enter Server Port Number");
		String port = s.nextLine();
		return Integer.parseInt(port);
	}
	
	public String GetServerPrivateKey()
	{
		System.out.println("Enter Server Private key File Location");
		String pvtKeyFile = s.nextLine();
		return pvtKeyFile;
	}
	
	public String GetClientPublicKey()
	{
		System.out.println("Enter Client Public key File Location");
		String pubKeyFile = s.nextLine();
		return pubKeyFile;
	}
	
}


class s_SocketConnection
{
	private Socket socket;
	private ServerSocket serverSocket;
	
	public s_SocketConnection(int port) {
		CreateSocket(port);
	}
	
	private void CreateSocket(int port) {
		try {
			serverSocket = new ServerSocket(port);
			System.out.println("Server started"); 
            System.out.println("Waiting for a client ..."); 
			socket = serverSocket.accept();
			System.out.println("Client accepted"); 
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}		
	}
	
	public void CloseSocket()
	{
		try {
			System.out.println("Closing connection"); 
			socket.close();
			serverSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}	
	}
	
	public void SendDataToClient(Object data)
	{
		try {
			ObjectOutputStream outStream = new ObjectOutputStream(socket.getOutputStream());
			outStream.writeObject(data);
			outStream.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public Object GetDataFromClient()
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