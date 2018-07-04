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

public class ShCipher {
	
	// keytool -exportcert -alias myserverkeys -keystore serverpub.jks -rfc -file serverpub.pem
	

	private static final String SHA256WITH_RSA = "SHA256withRSA";
	private static final String RSA = "RSA";
	private static final String JKS = "JKS";
	
	private String keyStorePathName = null;
	private String pwd = null;
	private String alias = null;
	private String cert = null;
	private KeyPair keypair = null;
	

	public ShCipher(String keyStorePathName, String pwd, String alias, String cert) throws Exception {
		super();
		this.keyStorePathName = keyStorePathName;
		this.pwd = pwd;
		this.alias = alias;
		this.cert = cert;
		this.keypair = this.getJks();
		
		
		
	}
	
	public ShCipher(String keyStorePathName, String pwd, String alias, String cert,String pubFile) throws Exception {
		super();
		this.keyStorePathName = keyStorePathName;
		this.pwd = pwd;
		this.alias = alias;
		this.cert = cert;
		this.keypair = this.getJks();
		this.generatePublicKey(pubFile);
		
		
	}

	public void generatePublicKey(String pubFile) throws IOException {
		Path p = Paths.get(pubFile);
		if(!p.toFile().exists()) {
			Files.write(p, keypair.getPublic().getEncoded(), StandardOpenOption.CREATE);
		}
	}
	
	
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
		
		return keypair;
		
	}
		
	public byte[] encode(byte[] content) throws Exception {
		
				
		Cipher ciph = Cipher.getInstance(RSA);
		ciph.init(Cipher.ENCRYPT_MODE, keypair.getPrivate());
		byte[] crypt = ciph.doFinal(content);
		return Base64.getEncoder().encode(crypt);
	}
	
	
	public byte[] signContent(byte[]  content) throws Exception {
		
		Signature signature = Signature.getInstance(SHA256WITH_RSA);
		signature.initSign(keypair.getPrivate());
		signature.update(content);
		
		return signature.sign();
	}
	
	
}
