package test.com.sh.cloud.security;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.junit.Test;

import com.sh.cloud.security.ShCipher;
import com.sh.cloud.security.ShDecoder;

public class ShCipherTest {

	@Test
	public void testApp() throws Exception {
		
		InputStream iStr = getClass().getResourceAsStream("/test.jks");
		String copyname = "test.jks";
		Files.copy(iStr, Paths.get(copyname), StandardCopyOption.REPLACE_EXISTING);
		String pwd = "test1234";
		String alias = "test";
		String cert = "test";
		String pubFile = "secret.pub";
		ShCipher cph = new ShCipher(copyname, pwd, alias, cert,pubFile);
		ShDecoder dec = new ShDecoder(pubFile);
		
		byte[] b = cph.encode("WEEEE".getBytes());		
		String res = dec.decode(b);
		cph.signContent("CONTENT".getBytes());
		cph = new ShCipher(copyname, pwd, alias, cert);
		
		new File(pubFile).delete();
		new File(copyname).delete();
		System.out.println(res);
	}

}
