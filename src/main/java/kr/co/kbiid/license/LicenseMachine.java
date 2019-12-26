package kr.co.kbiid.license;

import java.io.File;
import java.io.IOException;
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

/**
 * 라이선스 발급, 검증을 하는 기능이 있는 클래스
 * 
 * @author kbiid
 */
public class LicenseMachine {

	private static Log logger = LogFactory.getLog(License.class);

	/**
	 * 공개키 파일로부터 공개키를 얻어 라이선스를 암호화하는 메서드
	 * 
	 * @param license 라이선스 정보가 담긴 License객체
	 * @param publicKeyFile 공개키에 대한 File 객체
	 * @return byte[]
	 * @throws Exception
	 */
	public static byte[] issue(License license, File publicKeyFile) throws Exception {

		logger.info("issue start..");
		PublicKey publicKey = KeyUtil.getPublicKeyByFile(publicKeyFile.getAbsolutePath()); // 파일로부터 공개키를 얻어옴
		return generateLicense(license, publicKey);
	}

	/**
	 * 공개키를 이용하여 라이선스를 암호화하는 메서드
	 * 
	 * @param license 라이선스 정보가 담긴 License객체
	 * @param publicKey PublicKey클래스 객체
	 * @return byte[]
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	private static byte[] generateLicense(License license, PublicKey publicKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

		logger.info("generateLicense..");
		String plainText = license.toStringWithDelimeter(); // license를 만들기 전 license의 정보를 문자열로 변환함(Delimeter : "|").
		return CipherUtil.encryptRSA(plainText, publicKey);
	}

	/**
	 * Base64로 인코딩된 공개키 문자열을 이용하여 라이선스를 암호화하는 메서드
	 * 
	 * @param license 라이선스 정보가 담긴 License객체
	 * @param publicKeyString Base64로 인코딩된 공개키 문자열
	 * @return byte[]
	 * @throws Exception
	 */
	public static byte[] issue(License license, String publicKeyString) throws Exception {

		logger.info("issue start..");
		PublicKey publicKey = KeyUtil.getPublicKeyByString(publicKeyString);
		return generateLicense(license, publicKey);
	}

	/**
	 * 개인키 파일로부터 개인키를 얻어 라이선스를 암호화하는 메서드
	 * 
	 * @param license 라이선스 정보가 담긴 License객체
	 * @param privateKeyFile 개인키에 대한 File 객체
	 * @return byte[]
	 * @throws Exception
	 */
	public static byte[] issueByPrivate(License license, File privateKeyFile) throws Exception {

		logger.info("issue start..");
		PrivateKey privateKey = KeyUtil.getPrivateKeyByFile(privateKeyFile.getAbsolutePath());
		return generateLicense(license, privateKey);
	}

	/**
	 * 개인키를 이용하여 라이선스를 암호화하는 메서드
	 * 
	 * @param license 라이선스 정보가 담긴 License객체
	 * @param privateKey PrivateKey 클래스 객체
	 * @return byte[]
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	private static byte[] generateLicense(License license, PrivateKey privateKey) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

		logger.info("generateLicense..");
		String plainText = license.toStringWithDelimeter(); // license를 만들기 전 license의 정보를 문자열로 변환함(Delimeter : "|").
		return CipherUtil.encryptRSA(plainText, privateKey);
	}

	/**
	 * Base64로 인코딩된 개인키 문자열을 이용하여 라이선스를 암호화하는 메서드
	 * 
	 * @param license 라이선스 정보가 담긴 License객체
	 * @param privateKeyString Base64로 인코딩된 개인키 문자열
	 * @return byte[]
	 * @throws Exception
	 */
	public static byte[] issueByPrivate(License license, String privateKeyString) throws Exception {

		logger.info("issue start..");
		PrivateKey privateKey = KeyUtil.getPrivateKeyByString(privateKeyString);
		return generateLicense(license, privateKey);
	}

	/**
	 * 라이선스 파일을 개인키 파일로부터 개인키를 얻어 복호화 후 검증하는 메서드
	 * 
	 * @param licensePath 라이선스 파일이 저장되어 있는 경로
	 * @param privateKeyPath 개인키가 저장되어 있는 경로
	 * @return 검증 성공시 true, 실패시 false
	 * @throws Exception
	 */
	public static boolean verify(String licensePath, String privateKeyPath) throws Exception {

		logger.info("verify start..");
		PrivateKey privateKey = KeyUtil.getPrivateKeyByFile(privateKeyPath);
		return verifyLicense(FileUtil.readFile(licensePath), privateKey);
	}
	
	/**
	 * 개인키를 이용하여 복호화하는 메서드
	 * 
	 * @param encrypted 라이선스 파일을 바이트 배열로 읽어온 결과 값
	 * @param privateKey PrivateKey클래스 객체
	 * @return 검증 성공시 true, 실패시 false
	 */
	private static boolean verifyLicense(byte[] encrypted, PrivateKey privateKey) {
		logger.info("verifyLicense..");

		try {
			String plainText = CipherUtil.decryptRSA(encrypted, privateKey);
			String[] result = plainText.split("\\|");
			return checkResult(result);
		} catch (Exception e) {
			logger.error(e.getMessage());
			return false;
		}
	}

	/**
	 * license의 복호화한 내용이 유효한지 검사하기 위한 메서드
	 * 
	 * @param result 라이선스 파일을 복호화한 후 구분자로 나눈 문자열 배열
	 * @return 유효할시 true, 유효하지 않을 시 false
	 * @throws SocketException
	 */
	private static boolean checkResult(String[] result) throws SocketException {
		
		LocalDate expirationDate = LocalDate.parse(result[2], DateTimeFormatter.ISO_DATE);

		if (result[0].equals(HostInfoUtil.getHostName()) && HostInfoUtil.getLocalMacAddresses().contains(result[1])
				&& !LocalDate.now().isAfter(expirationDate)) {
			return true;
		}
		return false;
	}

	/**
	 * Base64로 인코딩된 개인키 문자열을 이용하여 라이선스를 복호화하는 메서드
	 * 
	 * @param encrypted 라이선스 파일을 바이트 배열로 읽어온 결과 값
	 * @param privateKeyString Base64로 인코딩된 개인키 문자열
	 * @return 검증 성공시 true, 실패시 false
	 * @throws Exception
	 */
	public static boolean verify(byte[] encrypted, String privateKeyString) throws Exception {
		
		logger.info("verify start..");
		PrivateKey privateKey = KeyUtil.getPrivateKeyByString(privateKeyString);
		return verifyLicense(encrypted, privateKey);
	}

	/**
	 * 라이선스 파일을 공개키 파일로부터 공개키를 얻어 복호화 후 검증하는 메서드
	 * 
	 * @param licensePath 라이선스 파일이 저장되어 있는 경로
	 * @param publicKeyPath 공개키가 저장되어 있는 경로
	 * @return 검증 성공시 true, 실패시 false
	 * @throws Exception
	 */
	public static boolean verifyByPublic(String licensePath, String publicKeyPath) throws Exception {

		logger.info("verify start..");
		PublicKey publicKey = KeyUtil.getPublicKeyByFile(publicKeyPath);
		return verifyLicense(FileUtil.readFile(licensePath), publicKey);
	}

	/**
	 * 공개키를 이용하여 복호화하는 메서드
	 * 
	 * @param encrypted 라이선스 파일을 바이트 배열로 읽어온 결과 값
	 * @param publicKey PublicKey클래스 객체
	 * @return 검증 성공시 true, 실패시 false
	 */
	private static boolean verifyLicense(byte[] encrypted, PublicKey publicKey) {
		
		logger.info("verifyLicense..");
		try {
			String plainText = CipherUtil.decryptRSA(encrypted, publicKey);
			String[] result = plainText.split("\\|");
			return checkResult(result);
		} catch (Exception e) {
			logger.error(e.getMessage());
			return false;
		}
	}

	/**
	 * Base64로 인코딩된 공개키 문자열을 이용하여 라이선스를 복호화하는 메서드
	 * 
	 * @param encrypted 라이선스 파일을 바이트 배열로 읽어온 결과 값
	 * @param publicKeyString Base64로 인코딩된 공개키 문자열
	 * @return 검증 성공시 true, 실패시 false
	 * @throws Exception
	 */
	public static boolean verifyByPublic(byte[] encrypted, String publicKeyString) throws Exception {
		
		logger.info("verify start..");
		PublicKey publicKey = KeyUtil.getPublicKeyByString(publicKeyString);
		return verifyLicense(encrypted, publicKey);
	}

}
