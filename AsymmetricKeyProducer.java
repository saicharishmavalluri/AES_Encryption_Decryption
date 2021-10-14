import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.SecureRandom;

public class AsymmetricKeyProducer {
	public static void main(String args[]) throws IOException
	{	

		try (Scanner sc = new Scanner(System.in)) {
			//provide the inputs
			System.out.println("Enter the public key file path");
			String publicKey = sc.next();
			System.out.println("Enter the private key file path");
			String privateKey = sc.next();
			SecureRandom rand = new SecureRandom();
			KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		kpg.initialize(2048,rand);
		KeyPair kp = kpg.generateKeyPair();
		PublicKey keyPublic = kp.getPublic();
		PrivateKey keyPrivate = kp.getPrivate();

		//Store Public Key to file
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPublic.getEncoded());
		FileOutputStream fos = null;
		try {
				fos = new FileOutputStream(publicKey);
				System.out.println("Stored Public Key in given location");
		} catch (FileNotFoundException e) {
					
					e.printStackTrace();
		}
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
		//Store Private Key to file
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPrivate.getEncoded());
		FileOutputStream fos1 = null;
		try {
			fos1 = new FileOutputStream(privateKey);
			System.out.println("Stored Private Key in given location");
		} catch (FileNotFoundException e) {
					e.printStackTrace();
		}
		fos1.write(pkcs8EncodedKeySpec.getEncoded());
		fos1.close();
		}
	}
}
