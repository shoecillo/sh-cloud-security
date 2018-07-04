package com.sh.cloud.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class ShDecoder {

	private static final String UTF_8 = "UTF-8";
	private static final String RSA = "RSA";	
	private String pubFile = null;

	public ShDecoder(String pubFile) {
		super();
		this.pubFile = pubFile;
		
	}

	public String decode(byte[] content) throws Exception {

		// KeyPair keypair = getJks();
		Cipher ciph = Cipher.getInstance(RSA);
		ciph.init(Cipher.DECRYPT_MODE, getPublicCert());
		byte[] b = Base64.getDecoder().decode(content);
		String dec = new String(ciph.doFinal(b), UTF_8);
		return dec;
	}

	public PublicKey getPublicCert() throws Exception {

		Path p = Paths.get(pubFile);
		byte[] keyBytes = Files.readAllBytes(p);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(RSA);
		return kf.generatePublic(spec);

	}

}
