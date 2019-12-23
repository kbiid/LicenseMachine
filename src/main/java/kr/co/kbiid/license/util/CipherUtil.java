package kr.co.kbiid.license.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class CipherUtil {

	private static Log logger = LogFactory.getLog(CipherUtil.class);

	/**
	 * Public Key로 암호화를 수행함
	 * 
	 * @param plainText 암호화할 평문
	 * @param publicKey 공개키
	 */
	public static byte[] encryptRSA(String plainText, PublicKey publicKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		logger.info("encryptRSA start..");
		Cipher cipher = Cipher.getInstance("RSA");

		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] bytePlain = cipher.doFinal(plainText.getBytes());

		return bytePlain;
	}

	/**
	 * Private Key로 암호화를 수행함
	 * 
	 * @param plainText  암호화할 평문
	 * @param privateKey 개인키
	 */
	public static byte[] encryptRSA(String plainText, PrivateKey privateKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		logger.info("encryptRSA start..");
		Cipher cipher = Cipher.getInstance("RSA");

		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] bytePlain = cipher.doFinal(plainText.getBytes());

		return bytePlain;
	}

	/**
	 * Private Key로 RSA 복호화를 수행
	 * 
	 * @param encrypted  암호화된 이진데이터를 base64 인코딩한 문자열
	 * @param privateKey 복호화를 위한 개인키
	 */
	public static String decryptRSA(byte[] encrypted, PrivateKey privateKey)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException, UnsupportedEncodingException {

		logger.info("decryptRSA start..");
		Cipher cipher = Cipher.getInstance("RSA");

		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] bytePlain = cipher.doFinal(encrypted);
		String decrypted = new String(bytePlain, "utf-8");

		return decrypted;
	}

	/**
	 * Public Key로 RSA 복호화를 수행
	 * 
	 * @param encrypted 암호화된 이진데이터를 base64 인코딩한 문자열
	 * @param publicKey 복호화를 위한 공개키
	 */
	public static String decryptRSA(byte[] encrypted, PublicKey publicKey)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException, UnsupportedEncodingException {

		logger.info("decryptRSA start..");
		Cipher cipher = Cipher.getInstance("RSA");

		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] bytePlain = cipher.doFinal(encrypted);
		String decrypted = new String(bytePlain, "utf-8");

		return decrypted;
	}

}
