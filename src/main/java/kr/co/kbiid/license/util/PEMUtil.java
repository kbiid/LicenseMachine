package kr.co.kbiid.license.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * 이 클래스는 pem형식의 파일을 읽고 키를 얻기 위하여 사용한다.
 * 
 * @author kbiid
 */
public class PEMUtil {

	/**
	 * PEM 파일의 내용을 읽어 바이트 배열로 반환한다.
	 * 
	 * @param pemFile PEM 파일
	 * @return byte[] 바이트 배열로 변환한 PEM 파일
	 * @throws IOException
	 */
	private static byte[] parsePEMFile(File pemFile) throws IOException {
		if (!pemFile.isFile() || !pemFile.exists()) {
			throw new FileNotFoundException(String.format("경로(%s)에 파일이 존재하지 않습니다.", pemFile.getAbsolutePath()));
		}
		PemReader pemReader = new PemReader(new FileReader(pemFile));
		PemObject pemObject = pemReader.readPemObject();
		byte[] content = pemObject.getContent();
		pemReader.close();
		return content;
	}

	/**
	 * 바이트 배열 형태의 공캐키에서 공개키를 얻는다.
	 * 
	 * @param keyBytes  공개키의 바이트 배열 형태
	 * @param algorithm 사용할 암호화 알고리즘
	 * @return PublicKey 공개키
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PublicKey getPublicKey(byte[] keyBytes, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePublic(keySpec);
	}

	/**
	 * 바이트 배열 형태의 개인키에서 개인키를 얻는다.
	 * 
	 * @param keyBytes  개인키의 바이트 배열 형태
	 * @param algorithm 사용할 암호화 알고리즘
	 * @return PrivateKey 개인키
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePrivate(keySpec);
	}

	/**
	 * PEM 파일에서 공개키를 얻는다.
	 * 
	 * @param pemFilePath 공개키가 들어있는 PEM 파일
	 * @param algorithm   사용할 암호화 알고리즘
	 * @return PublicKey 공개키
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey readPublicKeyFromFile(String pemFilePath, String algorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		byte[] bytes = PEMUtil.parsePEMFile(new File(pemFilePath));
		return PEMUtil.getPublicKey(bytes, algorithm);
	}

	/**
	 * PEM 파일에서 개인키를 얻는다.
	 * 
	 * @param pemFilePath 개인키가 들어있는 PEM 파일
	 * @param algorithm   사용할 암호화 알고리즘
	 * @return PrivateKey 개인키
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey readPrivateKeyFromFile(String pemFilePath, String algorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

		byte[] bytes = PEMUtil.parsePEMFile(new File(pemFilePath));
		return PEMUtil.getPrivateKey(bytes, algorithm);
	}

}
