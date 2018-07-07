package test.com.sh.cloud.security;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.junit.Before;
import org.junit.Test;

import com.sh.cloud.security.ShCipher;
import com.sh.cloud.security.ShDecoder;

public class ShCipherTest {
	
	private String copyname = "test.jks";
	
	@Before
	public void config() throws Exception {
		InputStream iStr = getClass().getResourceAsStream("/test.jks");		
		Files.copy(iStr, Paths.get(copyname), StandardCopyOption.REPLACE_EXISTING);
		iStr.close();
	}

	@Test
	public void testApp() throws Exception {
		
		Boolean isBase64 = false;
		String pwd = "test1234";
		String alias = "test";
		String cert = "test";
		String pubFile = "secret.pub";
		ShCipher cph = new ShCipher(copyname, pwd, alias, cert,pubFile,isBase64);
		ShDecoder dec = new ShDecoder(pubFile,isBase64);
		
		byte[] b = cph.encode("WEEEE".getBytes());		
		String res = new String(dec.decode(b),"UTF-8");
		cph.signContent("CONTENT".getBytes());
		cph = new ShCipher(copyname, pwd, alias, cert);
		
		new File(pubFile).delete();
		new File(copyname).delete();
		System.out.println(res);
	}
	
	@Test
	public void testAppBase64() throws Exception {
		
		Boolean isBase64 = true;
		String pwd = "test1234";
		String alias = "test";
		String cert = "test";
		String pubFile = "secret.pub";
		ShCipher cph = new ShCipher(copyname, pwd, alias, cert,pubFile,isBase64);
		ShDecoder dec = new ShDecoder(pubFile,isBase64);
		
		byte[] b = cph.encode("WEEEE-Base64".getBytes());		
		String res = new String(dec.decode(b),"UTF-8");
		cph.signContent("CONTENT".getBytes());
		cph = new ShCipher(copyname, pwd, alias, cert);
		
		new File(pubFile).delete();
		new File(copyname).delete();
		System.out.println(res);
	}

}
