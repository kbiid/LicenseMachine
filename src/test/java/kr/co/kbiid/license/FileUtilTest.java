package kr.co.kbiid.license;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.KeyUtil;

public class FileUtilTest {

	private static Log logger = LogFactory.getLog(FileUtilTest.class);

	private String licensePath = "D:\\eclipse_workspace\\license-machine\\file\\license_test";
	private String data = "V4kOjZnlQpmJ4StdjQCXOXHwPuCC4DHxOlFjucody2nXj5g0M52PHUJMnRotY1rYcN99SdiCooLCa5qOIA6PWfSQ3oeUB9GdKt4TS/8qyLiEdzCaM0IXSrn37gd7bRXbf87HZrRqV8C07Fnnf7HgMhrIDP2g1IvUGyz81tODZ5wYFk4ujMs6JLphsZErTiKZ0iJagrximkPNdBvJee0ojMcYUO8Jz4Hc0QYgvIPqR4seChXaoAWArtcm3QRuZcxqef/X+DZFR7Ed4lWcmv9Lqpcq2tKLYEhkrNrqAdM/GwwURlozwKYpHMakptjUaZsyfsbqtEARHy9JzgkqNH3rHA==";

	@Test
	public void testMakeFile() throws NullPointerException, IOException {
		FileUtil.makeFile(licensePath, KeyUtil.toByteByBase64(data));
	}

	@Test
	public void testReadFile() throws NullPointerException, IOException {
		byte[] result = FileUtil.readFile(licensePath);
		logger.info(KeyUtil.toStringByBase64(result));
		Assert.assertNotNull(result);
	}

}
