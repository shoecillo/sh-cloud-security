package com.sh.cloud.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Base64;

import javax.crypto.Cipher;



/**
 * Cipher with JKS keyPair
 * @author shoe011
 * 
 * ######################################################################
 * ### COMMANDS TO CREATE AND LIST JAVA KEY STORE (JKS)                 #
 * #keytool -genkey -alias bootauth -keyalg RSA -keystore BootAuth.jks  #
 * #keytool -list -v -keystore keystore.jks                             #
 * ######################################################################
 *
 */
public class ShCipher {
	
	private static final String SHA256WITH_RSA = "SHA256withRSA";
	private static final String RSA = "RSA";
	private static final String JKS = "JKS";
	
	private String keyStorePathName = null;
	private String pwd = null;
	private String alias = null;
	private String cert = null;
	private Boolean isBase64Key = null;
	private KeyPair keypair = null;
	
	/**
	 * Constructor without create public key file
	 * @param keyStorePathName - jks path
	 * @param pwd - keystore password 
	 * @param alias - keystore alias
	 * @param cert -certificate alias
	 * @throws Exception
	 */
	public ShCipher(String keyStorePathName, String pwd, String alias, String cert) throws Exception {
		super();
		this.keyStorePathName = keyStorePathName;
		this.pwd = pwd;
		this.alias = alias;
		this.cert = cert;
		this.keypair = this.getJks();
		
	}
	
	/**
	 * Constructor that create public key file 
	 * @param keyStorePathName - jks path
	 * @param pwd - keystore password 
	 * @param alias - keystore alias
	 * @param cert -certificate alias
	 * @param pubFile - path where you want create the public key file
	 * @param isBase64Key - true if want Base64 file, false if want binary file
	 * @throws Exception
	 */
	public ShCipher(String keyStorePathName, String pwd, String alias, String cert,String pubFile,Boolean isBase64Key) throws Exception {
		super();
		this.keyStorePathName = keyStorePathName;
		this.pwd = pwd;
		this.alias = alias;
		this.cert = cert;
		this.isBase64Key = isBase64Key;
		this.keypair = this.getJks();
		if(this.isBase64Key) {
			this.generateBase64PublicKey(pubFile);
		}else {
			this.generatePublicKey(pubFile);
		}
		
		
	}
	
	/**
	 * Create a new public key file
	 * @param pubFile - path where you want to save the key
	 * @throws IOException
	 */
	public void generatePublicKey(String pubFile) throws IOException {
		Path p = Paths.get(pubFile);
		if(!p.toFile().exists()) {
			Files.write(p, keypair.getPublic().getEncoded(), StandardOpenOption.CREATE);
		}
	}
	
	/**
	 * Create a public key file encoded in Base64
	 * @param pubFile - path where you want to save the key
	 * @throws IOException
	 */
	public void generateBase64PublicKey(String pubFile) throws IOException {
		
		Path p = Paths.get(pubFile);
		if(!p.toFile().exists()) {
			byte[] b64 = Base64.getEncoder().encode(keypair.getPublic().getEncoded());
			Files.write(p, b64, StandardOpenOption.CREATE);
		}
		
	}
	
	/**
	 * Get the KeyPair of JKS
	 * @return KeyPair
	 * @throws Exception
	 */
	private KeyPair getJks() throws Exception {
		
		Path pathKeystore = Paths.get(keyStorePathName);
		KeyStore keyStore = KeyStore.getInstance(JKS);
		
		InputStream iStr = Files.newInputStream(pathKeystore, StandardOpenOption.READ);
		
		keyStore.load(iStr, pwd.toCharArray());
		
		Key key = keyStore.getKey(alias, pwd.toCharArray());
		KeyPair keypair = null;
		if (key instanceof PrivateKey) {
		      Certificate cert = keyStore.getCertificate(this.cert);
		      PublicKey publicKey = cert.getPublicKey();
		      keypair = new KeyPair(publicKey, (PrivateKey) key);
		}
		
		iStr.close();
		return keypair;
		
	}
	/**
	 * Encode bytes content with configured JKS	
	 * @param content - byte[]
	 * @return byte[] - encoded content in base64
	 * @throws Exception
	 */
	public byte[] encode(byte[] content) throws Exception {
		
				
		Cipher ciph = Cipher.getInstance(RSA);
		ciph.init(Cipher.ENCRYPT_MODE, keypair.getPrivate());
		byte[] crypt = ciph.doFinal(content);
		return Base64.getEncoder().encode(crypt);
	}
	
	/**
	 * Sign a content with configured JKS
	 * @param content - byte[]
	 * @return byte[] - signed content
	 * @throws Exception
	 */
	public byte[] signContent(byte[]  content) throws Exception {
		
		Signature signature = Signature.getInstance(SHA256WITH_RSA);
		signature.initSign(keypair.getPrivate());
		signature.update(content);
		
		return signature.sign();
	}
	
	
}
