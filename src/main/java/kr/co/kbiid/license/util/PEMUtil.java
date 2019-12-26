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
 * pem형식의 파일을 읽고 키를 얻기 위한 클래스
 * 
 * @author kbiid
 */
public class PEMUtil {

	/** pem 파일에서 내용을 읽어오는 메서드 */
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

	private static PublicKey getPublicKey(byte[] keyBytes, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePublic(keySpec);
	}

	private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePrivate(keySpec);
	}

	public static PublicKey readPublicKeyFromFile(String filePath, String algorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] bytes = PEMUtil.parsePEMFile(new File(filePath));
		return PEMUtil.getPublicKey(bytes, algorithm);
	}

	public static PrivateKey readPrivateKeyFromFile(String filePath, String algorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] bytes = PEMUtil.parsePEMFile(new File(filePath));
		return PEMUtil.getPrivateKey(bytes, algorithm);
	}
	
}
