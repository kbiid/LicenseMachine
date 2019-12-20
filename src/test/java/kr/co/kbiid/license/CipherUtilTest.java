package kr.co.kbiid.license;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import kr.co.kbiid.license.util.CipherUtil;
import kr.co.kbiid.license.util.KeyUtil;

public class CipherUtilTest {

	private static Log logger = LogFactory.getLog(CipherUtilTest.class);

	private String plainText = "test123!@#";
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	private static byte[] encrypted;

	@BeforeClass
	public static void setUp() throws Exception {
		KeyPair keyPair = KeyUtil.genRSAKeyPair();
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();
	}

	@Ignore
	@Test
	public void encryptRSA() throws Exception {
		encrypted = CipherUtil.encryptRSA(plainText, publicKey);
		logger.info(KeyUtil.toStringByBase64(encrypted));
	}

	@Ignore
	@Test
	public void decryptRSA() throws Exception {
		String result = CipherUtil.decryptRSA(encrypted, privateKey);
		logger.info(result);
	}
	
	@Test
	public void encryptRSAByPrivate() throws Exception {
		encrypted = CipherUtil.encryptRSA(plainText, privateKey);
		logger.info(KeyUtil.toStringByBase64(encrypted));
	}
	
	@Test
	public void decryptRSAByPublic() throws Exception {
		String result = CipherUtil.decryptRSA(encrypted, publicKey);
		logger.info(result);
	}

}
