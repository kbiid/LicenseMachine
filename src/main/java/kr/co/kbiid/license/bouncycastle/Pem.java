package kr.co.kbiid.license.bouncycastle;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Key;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class Pem {

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
