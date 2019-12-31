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
	 * Public Key로 암호화를 수행한다.
	 * 
	 * @param plainText 암호화할 평문
	 * @param publicKey 공개키
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] encryptRSA(String plainText, PublicKey publicKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		logger.info("encryptRSA start..");
		
		// RSA Cipher 객체 생성
		Cipher cipher = Cipher.getInstance("RSA");

		// 암호화 Cipher 초기화
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
		// 암호화 완료
		byte[] bytePlain = cipher.doFinal(plainText.getBytes());

		return bytePlain;
	}

	/**
	 * Private Key로 암호화를 수행한다.
	 * 
	 * @param plainText  암호화할 평문
	 * @param privateKey 개인키
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
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
	 * Private Key로 RSA 복호화를 수행한다.
	 * 
	 * @param encrypted  암호화된 이진데이터를 base64 인코딩한 문자열
	 * @param privateKey 복호화를 위한 개인키
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws UnsupportedEncodingException
	 */
	public static String decryptRSA(byte[] encrypted, PrivateKey privateKey)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException, UnsupportedEncodingException {

		logger.info("decryptRSA start..");
		
		// RSA Cipher 객체 생성
		Cipher cipher = Cipher.getInstance("RSA");

		// 복호화 Cipher 초기화
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		// 복호화 완료
		byte[] bytePlain = cipher.doFinal(encrypted);
		
		String decrypted = new String(bytePlain, "utf-8");
		return decrypted;
	}

	/**
	 * Public Key로 RSA 복호화를 수행한다.
	 * 
	 * @param encrypted 암호화된 이진데이터를 base64 인코딩한 문자열
	 * @param publicKey 복호화를 위한 공개키
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws UnsupportedEncodingException
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
