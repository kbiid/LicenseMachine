package kr.co.kbiid.license;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import kr.co.kbiid.license.util.CipherUtil;
import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.HostInfoUtil;
import kr.co.kbiid.license.util.KeyUtil;

public class LicenseMachine {

	private static Log logger = LogFactory.getLog(License.class);

	public static byte[] issue(License license, File file) throws Exception {

		logger.info("issue start..");
		PublicKey publicKey = KeyUtil.getPublicKeyByFile(file.getAbsolutePath());
		return generateLicense(license, publicKey);
	}

	private static byte[] generateLicense(License license, PublicKey publicKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

		logger.info("generateLicense..");
		// license를 만들기 전 license의 정보를 문자열로 변환함(Delimeter : "|").
		String plainText = license.toStringWithDelimeter();

		return CipherUtil.encryptRSA(plainText, publicKey);
	}

	public static byte[] issue(License license, String publicKeyString) throws Exception {

		logger.info("issue start..");
		PublicKey publicKey = KeyUtil.getPublicKeyByString(publicKeyString);
		return generateLicense(license, publicKey);
	}

	public static byte[] issueByPrivate(License license, File file) throws Exception {

		logger.info("issue start..");
		PrivateKey privateKey = KeyUtil.getPrivateKeyByFile(file.getAbsolutePath());
		return generateLicense(license, privateKey);
	}

	private static byte[] generateLicense(License license, PrivateKey privateKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

		logger.info("generateLicense..");
		// license를 만들기 전 license의 정보를 문자열로 변환함(Delimeter : "|").
		String plainText = license.toStringWithDelimeter();

		return CipherUtil.encryptRSA(plainText, privateKey);
	}

	public static byte[] issueByPrivate(License license, String privateKeyString) throws Exception {

		logger.info("issue start..");
		PrivateKey privateKey = KeyUtil.getPrivateKeyByString(privateKeyString);
		return generateLicense(license, privateKey);
	}

	public static boolean verify(String licenseFullPath, String privateKeyFullPath) throws Exception {

		logger.info("verify start..");
		PrivateKey privateKey = KeyUtil.getPrivateKeyByFile(privateKeyFullPath);

		return verifyLicense(FileUtil.readFile(licenseFullPath), privateKey);
	}

	private static boolean verifyLicense(byte[] encrypted, PrivateKey privateKey)
			throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, SocketException {

		logger.info("verifyLicense..");

		String plainText = CipherUtil.decryptRSA(encrypted, privateKey);
		String[] result = plainText.split("\\|");

		return checkResult(result);
	}

	/**
	 * license의 복호화한 내용이 유효한지 검사하기 위한 메서드
	 */
	private static boolean checkResult(String[] result) throws SocketException {
		LocalDate expirationDate = LocalDate.parse(result[2], DateTimeFormatter.ISO_DATE);

		if (result[0].equals(HostInfoUtil.getHostName()) && HostInfoUtil.getLocalMacAddresses().contains(result[1])
				&& !LocalDate.now().isAfter(expirationDate)) {
			return true;
		}

		return false;
	}

	public static boolean verify(byte[] encrypted, String privateKeyString) throws Exception {
		logger.info("verify start..");
		PrivateKey privateKey = KeyUtil.getPrivateKeyByString(privateKeyString);

		return verifyLicense(encrypted, privateKey);
	}

	public static boolean verifyByPublic(String licenseFullPath, String publicKeyFullPath) throws Exception {

		logger.info("verify start..");
		PublicKey publicKey = KeyUtil.getPublicKeyByFile(publicKeyFullPath);

		return verifyLicense(FileUtil.readFile(licenseFullPath), publicKey);
	}

	private static boolean verifyLicense(byte[] encrypted, PublicKey publicKey)
			throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, SocketException {

		logger.info("verifyLicense..");

		String plainText = CipherUtil.decryptRSA(encrypted, publicKey);
		String[] result = plainText.split("\\|");

		return checkResult(result);
	}

	public static boolean verifyByPublic(byte[] encrypted, String publicKeyString) throws Exception {
		logger.info("verify start..");
		PublicKey publicKey = KeyUtil.getPublicKeyByString(publicKeyString);

		return verifyLicense(encrypted, publicKey);
	}

}
