package kr.co.kbiid.license.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class BouncyCastleUtil {

	private static Log logger = LogFactory.getLog(BouncyCastleUtil.class);

	private static final int KEY_SIZE = 1024;

	public static KeyPair genKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {

		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
		generator.initialize(KEY_SIZE);

		return generator.generateKeyPair();
	}

	public static void writePemFile(Key key, String description, String fileName)
			throws FileNotFoundException, IOException {

		Pem pemFile = new Pem(key, description);
		pemFile.write(fileName);

		logger.info(String.format("%s를 %s 파일로 내보냈습니다.", description, fileName));
	}
}

class Pem {

	private PemObject pemObject;

	public Pem(Key key, String description) {
		this.pemObject = new PemObject(description, key.getEncoded());
	}

	public void write(String fileName) throws FileNotFoundException, IOException {
		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(fileName)));

		try {
			pemWriter.writeObject(this.pemObject);
		} finally {
			pemWriter.close();
		}
	}
}