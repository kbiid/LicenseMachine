package kr.co.kbiid.license.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class KeyUtil {

	private static Log logger = LogFactory.getLog(KeyUtil.class);

	/**
	 * KeyPair를 생성한다.
	 * 
	 * @return KeyPair
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
		logger.info("genRSAKeyPair start..");

		SecureRandom secureRandom = new SecureRandom(); // 난수 생성을 위한 클래스
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA"); // RSA 알고리즘 KeyPairGenerator 객체 생성
		gen.initialize(1024, secureRandom); // 임의의 1024비트 사이즈로 KeyPairGenerator 객체 초기화

		KeyPair keyPair = gen.genKeyPair();
		return keyPair;
	}

	/**
	 * 개인키가 들어있는 파일에서 개인키얻는다.
	 * 
	 * @param privateKeyFilePath 개인키가 저장되어 있는 경로
	 * @return PrivateKey 개인키
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey getPrivateKeyByFile(String privateKeyFilePath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		logger.info("getPrivateKey..");

		String fileName = Paths.get(privateKeyFilePath).getFileName().toString();
		
		// PEM 파일일 경우
		if (fileName.contains(".pem")) {
			return PEMUtil.readPrivateKeyFromFile(privateKeyFilePath, "RSA");
		}
		
		byte[] keyBytes = Files.readAllBytes(Paths.get(privateKeyFilePath)); // PEM 파일이 아닐 경우
		return generatePrivateKey(keyBytes);
	}

	/**
	 * 바이트 배열 형태의 개인키에서 개인키를 얻는다.
	 * 
	 * @param keyBytes 개인키의 byte 배열
	 * @return PrivateKey 개인키
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PrivateKey generatePrivateKey(byte[] keyBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(spec);
	}

	/**
	 * Base64로 인코딩된 개인키 문자열에서 개인키를 얻는다.
	 * 
	 * @param privateKeyString Base64로 인코딩된 개인키 문자열
	 * @return PrivateKey 개인키
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey getPrivateKeyByString(String privateKeyString)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		logger.info("getPrivateKey..");
		return generatePrivateKey(toByteByBase64(privateKeyString));
	}

	/**
	 * 바이트 배열을 Base64로 인코딩된 문자열로 변환한다.
	 * 
	 * @param encrypted 암호화한 결과로 만들어진 바이트 배열
	 * @return String Base64로 인코딩된 바이트 배열
	 */
	public static String toStringByBase64(byte[] encrypted) {
		Encoder encoder = Base64.getEncoder();
		return encoder.encodeToString(encrypted);
	}

	/**
	 * Base64로 인코딩된 문자열을 바이트 배열로 변환하는 메서드 
	 * 
	 * @param encrypted Base64로 인코딩된 문자열
	 * @return byte[] 바이트 배열로 디코딩된 문자열
	 */
	public static byte[] toByteByBase64(String encrypted) {
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(encrypted);
	}

	/**
	 * 공개키가 들어있는 파일에서 공개키를 얻는다.
	 * 
	 * @param publicKeyFilePath 공개키가 저장되어 있는 경로
	 * @return PublicKey 공개키
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey getPublicKeyByFile(String publicKeyFilePath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		logger.info("getPublicKey..");
		
		String fileName = Paths.get(publicKeyFilePath).getFileName().toString();
		if (fileName.contains(".pem")) {
			return PEMUtil.readPublicKeyFromFile(publicKeyFilePath, "RSA");
		}
		byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyFilePath));
		return generatePublicKey(keyBytes);
	}
	
	/**
	 * 바이트 배열 형태의 공개키에서 공개키를 얻는다.
	 * 
	 * @param keyBytes 공개키의 byte 배열
	 * @return PublicKey 공개키
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PublicKey generatePublicKey(byte[] keyBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(keySpec);
	}

	/**
	 * Base64로 인코딩된 공개키 문자열에서 공개키를 얻는다.
	 * 
	 * @param publicKeyString Base64로 인코딩된 공개키 문자열
	 * @return PublicKey 공개키
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey getPublicKeyByString(String publicKeyString)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		logger.info("getPublicKeyByHexString..");
		return generatePublicKey(toByteByBase64(publicKeyString));
	}

}
