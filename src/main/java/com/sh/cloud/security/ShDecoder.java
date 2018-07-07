package com.sh.cloud.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

/**
 * Decoder asymetric key
 * @author shoe011
 *
 */
public class ShDecoder {

	private static final String RSA = "RSA";	
	private String pubFile = null;
	private Boolean isBase64Key = null;
	
	private PublicKey pbKey;
	
	/**
	 * Constructor for Decoder.Load a Public Key
	 * @param pubFile
	 * @param isBase64Key
	 * @throws Exception 
	 */
	public ShDecoder(String pubFile,Boolean isBase64Key) throws Exception {
		super();
		this.pubFile = pubFile;
		this.isBase64Key = isBase64Key;
		this.pbKey = this.getPublicCert();
	}
	
	/**
	 * Decrypt a bytes content with public Key
	 * @param content - byte[] content in base64
	 * @return byte[] - Decoded content
	 * @throws Exception
	 */
	public byte[] decode(byte[] content) throws Exception {

		Cipher ciph = Cipher.getInstance(RSA);
		ciph.init(Cipher.DECRYPT_MODE,pbKey);
		byte[] b = Base64.getDecoder().decode(content);
		return ciph.doFinal(b);
	}
	
	/**
	 * Get PublicKey object
	 * @return PublicKey
	 * @throws Exception
	 */
	private PublicKey getPublicCert() throws Exception {

		Path p = Paths.get(pubFile);
		byte[] keyBytes = Files.readAllBytes(p);
		if(isBase64Key) {
			keyBytes = Base64.getDecoder().decode(keyBytes);
		}
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(RSA);
		return kf.generatePublic(spec);

	}
}
