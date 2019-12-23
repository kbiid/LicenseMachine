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
	 * 1024비트 RSA 키쌍을 생성
	 */
	public static KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {
		logger.info("genRSAKeyPair start..");
		SecureRandom secureRandom = new SecureRandom();
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024, secureRandom);

		KeyPair keyPair = gen.genKeyPair();
		return keyPair;
	}

	public static PrivateKey getPrivateKeyByFile(String fileFullPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		logger.info("getPrivateKey..");
		if (Paths.get(fileFullPath).getFileName().toString().contains(".pem")) {
			return PEMUtil.readPrivateKeyFromFile(fileFullPath, "RSA");
		}
		byte[] keyBytes = Files.readAllBytes(Paths.get(fileFullPath));
		return generatePrivateKey(keyBytes);
	}

	private static PrivateKey generatePrivateKey(byte[] keyBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(spec);
	}

	public static PrivateKey getPrivateKeyByString(String privateKeyString)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		logger.info("getPrivateKey..");
		return generatePrivateKey(toByteByBase64(privateKeyString));
	}

	public static String toStringByBase64(byte[] encrypted) {
		Encoder encoder = Base64.getEncoder();
		return encoder.encodeToString(encrypted);
	}

	public static byte[] toByteByBase64(String encrypted) {
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(encrypted);
	}

	public static PublicKey getPublicKeyByFile(String fileFullPath)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		logger.info("getPublicKey..");
		if (Paths.get(fileFullPath).getFileName().toString().contains(".pem")) {
			return PEMUtil.readPublicKeyFromFile(fileFullPath, "RSA");
		}
		byte[] keyBytes = Files.readAllBytes(Paths.get(fileFullPath));
		return generatePublicKey(keyBytes);
	}

	private static PublicKey generatePublicKey(byte[] keyBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(keySpec);
	}

	public static PublicKey getPublicKeyByString(String publicKeyString)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		logger.info("getPublicKeyByHexString..");
		return generatePublicKey(toByteByBase64(publicKeyString));
	}

}
