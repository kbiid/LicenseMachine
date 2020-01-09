package kr.co.kbiid.license;

import java.time.LocalDate;

import javax.crypto.BadPaddingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.HostInfoUtil;

/*
 코드 상에서 키를 관리하여 암/복호화하는 테스트 케이스

선행 작업
1. keyUtilTest.java에서 genRSAKeyPair로 publicKey와 privateKey를 생성한 후 값을 확인하여 아래의 publicKey,privateKey 변수에 값을 저장한다.
2. 테스트 하고자 하는 라이선스의 정보를 License객체로 생성한다.
3. 라이선스가 유효하지 않은 경우를 테스트 하기 위하여 license_differentDate, license_differentMacAddress, license_differentHost를 각각 이름에 맞게 license의 내용과 다르게 설정하여 객체를 생성한다.

사용법
- 선행작업으로 설정된 변수들을 사용하여 테스트 코드들을 하나씩 실행시킨다.
- 실행 결과 라이선스 파일이 정상적으로 생성이 되는지 확인한다.
- license_modulated,license_over_length 같은 경우 정상적으로 생성된 license파일을 복사하여 이름을 수정하여 생성한 후 내용을 직접 수정한다.
*/
public class CipherJavaCodeTest {

	private Log logger = LogFactory.getLog(CipherJavaCodeTest.class);

	private String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCY0OQzhKWdIwJEGNtRoTXrXaejgn9bttQ2joA6sRjf9NYHkwyU8zjWxaNi+JkIZXd/zDmcUae5NwPoXy8a0ewxbzdJUq7kt0hP0vvTldwEZEcnuxrYw9bUBpA6oS7bFFVWll0bejacfZzIKMz/zXt+ZKC1zHMblk42uiTbiDkdNwIDAQAB";
	private String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAJjQ5DOEpZ0jAkQY21GhNetdp6OCf1u21DaOgDqxGN/01geTDJTzONbFo2L4mQhld3/MOZxRp7k3A+hfLxrR7DFvN0lSruS3SE/S+9OV3ARkRye7GtjD1tQGkDqhLtsUVVaWXRt6Npx9nMgozP/Ne35koLXMcxuWTja6JNuIOR03AgMBAAECgYEAihC5DJ68rpLxuiqnBEJdn8/W5NDDVk6BvuTSj7Rvn+/p65/8zxpMcSbRLlsikEZ0R99w8X2Ixrsg6bINsfKVrMzFsHQ/ydLR4wp37rZ5Iabe/AV3PX/MUNf+WUTEc3WBYyrOnufObMGHULC0VuLIeGSaiyzL+ckKh11uwISJguECQQDtdrXTASVG5p5u8nuLheUfG+/eeq1FdAKnQymIKt2wuBhH6tzjQsSVyCxUivn0s1D/+Tv08Y5EaNyuPpURUe4nAkEApL6lmx1eKnD21oPKILCPnwawcntqcamlt2IgImlsRk9g0OEQ8/r0AR04ptxdnANopqp+peok5e11/m+BB5XScQJBALYmTBy6ET0Mo9UY/Xmt0G4HgPzYf1b6QRrKYu5Ha1wmKsHnv144FhGKxa5oGIoCjox7QumF7Qo+oaCq8q+heBsCQFYNHwN+u4j/qG80N4gLsXknTVL/FAJ60oyPPKm810mCfNeeN/S4yGsskELYKC0tuqQTukN/ofZXqqJUK9mCcIECQQDBocZQMx9sEtZdaP7U+Q4finPaCUlGP7D0aBWEJJiwkws1bhkNWmHSFyeimYnarsuNmsgXTWAjjcYx0Xo5xZ5w";

	private License license = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().plusYears(1));
	private License license_differentDate = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().minusMonths(1));
	private License license_differentMacAddress = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-22",
			LocalDate.now().plusYears(1));
	private License license_differentHost = new License("kbiid", "D8-C4-97-D6-5F-92", LocalDate.now().plusYears(1));

	private String licensePath = "./file/javacode/license";
	private String differentDateLicensePath = "./file/javacode/license_different_date";
	private String differentMacAddressLicensePath = "./file/javacode/license_different_mac";
	private String differentHostPath = "./file/javacode/license_different_host";

	private String modulatedLicensePath = "./file/javacode/license_modulated";
	private String overLengthLicensePath = "./file/javacode/license_over_length";

	@Test
	public void cipher() {
		try {
			byte[] encrypted = LicenseMachine.issue(license, publicKey);
			FileUtil.makeFile(licensePath, encrypted);
			byte[] licenseByte = FileUtil.readFile(licensePath);
			boolean result = LicenseMachine.verify(licenseByte, privateKey);
			if (result) {
				logger.info("일치합니다.");
				Assert.assertTrue("일치합니다.", result);
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void verifyOverLengthLicense() {
		try {
			byte[] licenseByte = FileUtil.readFile(overLengthLicensePath);
			boolean result = LicenseMachine.verify(licenseByte, privateKey);
			if (result) {
				logger.info("일치합니다.");
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void verifyModulatedLicense() {
		try {
			byte[] licenseByte = FileUtil.readFile(modulatedLicensePath);
			boolean result = LicenseMachine.verify(licenseByte, privateKey);
			if (result) {
				logger.info("일치합니다.");
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch(BadPaddingException e) {
			Assert.fail("잘못된 라이센스 파일입니다.");
		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.getMessage());
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void differentDateLicense() {
		try {
			byte[] encrypted = LicenseMachine.issue(license_differentDate, publicKey);
			FileUtil.makeFile(differentDateLicensePath, encrypted);
			byte[] licenseByte = FileUtil.readFile(differentDateLicensePath);
			boolean result = LicenseMachine.verify(licenseByte, privateKey);
			if (result) {
				logger.info("일치합니다.");
				Assert.assertTrue("일치합니다.", result);
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void differentMacAddressLicense() {
		try {
			byte[] encrypted = LicenseMachine.issue(license_differentMacAddress, publicKey);
			FileUtil.makeFile(differentMacAddressLicensePath, encrypted);
			byte[] licenseByte = FileUtil.readFile(differentMacAddressLicensePath);
			boolean result = LicenseMachine.verify(licenseByte, privateKey);
			if (result) {
				logger.info("일치합니다.");
				Assert.assertTrue("일치합니다.", result);
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void differentHostNameLicense() {
		try {
			byte[] encrypted = LicenseMachine.issue(license_differentHost, publicKey);
			FileUtil.makeFile(differentHostPath, encrypted);
			byte[] licenseByte = FileUtil.readFile(differentHostPath);
			boolean result = LicenseMachine.verify(licenseByte, privateKey);
			if (result) {
				logger.info("일치합니다.");
				Assert.assertTrue("일치합니다.", result);
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void encryptByPrivateAndDecryptByPublic() {
		try {
			byte[] encrypted = LicenseMachine.issueByPrivate(license, privateKey);
			FileUtil.makeFile(licensePath, encrypted);
			byte[] licenseByte = FileUtil.readFile(licensePath);
			boolean result = LicenseMachine.verifyByPublic(licenseByte, publicKey);
			if (result) {
				logger.info("일치합니다.");
				Assert.assertTrue("일치합니다.", result);
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

}
