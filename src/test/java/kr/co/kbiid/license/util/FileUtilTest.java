package kr.co.kbiid.license.util;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.KeyUtil;

/**
*
* 선행 작업 
* - licensePath 변수에 license를 저장할 경로를 저장한다.
* - data에는 CipherUtilTest에서 encrypt로 생성한 값을 저장한다.
*
*/
public class FileUtilTest {

	private static Log logger = LogFactory.getLog(FileUtilTest.class);

	private String licensePath = "./file/license_test";
	private String data = "L/EWPezFfnX+Q/IR5Cs4CA/iVj8h5WP+aPuZTYK5tF8tAT296uyKbc6BpF+xV61bLzybav/u3OnnqofJcDsg3UgTWCkSCfFdBgMjwGkGlSjJNK/IZD2uO+vwBupC1IcrCSjG3a8/22vWTTNrwi7OhkOILp7ATNt0TJhPjQsOtrA=";

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
