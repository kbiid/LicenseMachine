package kr.co.kbiid.license;

import java.io.File;
import java.time.LocalDate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.HostInfoUtil;

public class CipherTest {

	private Log logger = LogFactory.getLog(CipherTest.class);

	private String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCY0OQzhKWdIwJEGNtRoTXrXaejgn9bttQ2joA6sRjf9NYHkwyU8zjWxaNi+JkIZXd/zDmcUae5NwPoXy8a0ewxbzdJUq7kt0hP0vvTldwEZEcnuxrYw9bUBpA6oS7bFFVWll0bejacfZzIKMz/zXt+ZKC1zHMblk42uiTbiDkdNwIDAQAB";
	private String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAJjQ5DOEpZ0jAkQY21GhNetdp6OCf1u21DaOgDqxGN/01geTDJTzONbFo2L4mQhld3/MOZxRp7k3A+hfLxrR7DFvN0lSruS3SE/S+9OV3ARkRye7GtjD1tQGkDqhLtsUVVaWXRt6Npx9nMgozP/Ne35koLXMcxuWTja6JNuIOR03AgMBAAECgYEAihC5DJ68rpLxuiqnBEJdn8/W5NDDVk6BvuTSj7Rvn+/p65/8zxpMcSbRLlsikEZ0R99w8X2Ixrsg6bINsfKVrMzFsHQ/ydLR4wp37rZ5Iabe/AV3PX/MUNf+WUTEc3WBYyrOnufObMGHULC0VuLIeGSaiyzL+ckKh11uwISJguECQQDtdrXTASVG5p5u8nuLheUfG+/eeq1FdAKnQymIKt2wuBhH6tzjQsSVyCxUivn0s1D/+Tv08Y5EaNyuPpURUe4nAkEApL6lmx1eKnD21oPKILCPnwawcntqcamlt2IgImlsRk9g0OEQ8/r0AR04ptxdnANopqp+peok5e11/m+BB5XScQJBALYmTBy6ET0Mo9UY/Xmt0G4HgPzYf1b6QRrKYu5Ha1wmKsHnv144FhGKxa5oGIoCjox7QumF7Qo+oaCq8q+heBsCQFYNHwN+u4j/qG80N4gLsXknTVL/FAJ60oyPPKm810mCfNeeN/S4yGsskELYKC0tuqQTukN/ofZXqqJUK9mCcIECQQDBocZQMx9sEtZdaP7U+Q4finPaCUlGP7D0aBWEJJiwkws1bhkNWmHSFyeimYnarsuNmsgXTWAjjcYx0Xo5xZ5w";
	private String publicKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\public_key.der";
	private String privateKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\private_key.der";

	private License license = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().plusYears(1));
	private License license2 = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().minusMonths(1));
	private String licensePath = "D:\\eclipse_workspace\\license-machine\\file\\license";
	private String licensePath2 = "D:\\eclipse_workspace\\license-machine\\file\\license2";

	private String modulatedLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\license_modulate";

	@Before
	public void setUp() {
		
	}
	
	@Test
	public void cipherWithKeyFileSuccess() {
		logger.info("byFile start..");
		logger.info("license info : " + license.toString());
		File file = new File(publicKeyPath);
		try {
			byte[] encrypted = LicenseMachine.issue(license, file);
			FileUtil.makeFile(licensePath, encrypted);
			boolean result = LicenseMachine.verify(licensePath, privateKeyPath);
			if (result) {
				logger.info("올바른 라이센스 파일입니다.");
			} else {
				Assert.fail("잘못된 라이센스 파일입니다.");
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}

	@Test
	public void cipherWithKeyFileLicenseModulated() {
		logger.info("byFile start..");
		logger.info("license info : " + license.toString());
		try {
			boolean result = LicenseMachine.verify(modulatedLicensePath, privateKeyPath);
			if (result) {
				logger.info("올바른 라이센스 파일입니다.");
			} else {
				throw new Exception();
			}
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail("잘못된 라이센스 파일입니다.");
		}
	}

	@Test
	public void cipherWithKeyFileHostInfoDifferent() {
		logger.info("byFile start..");
		logger.info("license info : " + license2.toString());
		File file = new File(publicKeyPath);
		try {
			byte[] encrypted = LicenseMachine.issue(license2, file);
			FileUtil.makeFile(licensePath2, encrypted);
			boolean result = LicenseMachine.verify(licensePath2, privateKeyPath);
			if (result) {
				logger.info("올바른 라이센스 파일입니다.");
			} else {
				Assert.fail("라이센스 정보가 올바르지 않습니다.");
			}
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail("잘못된 라이센스 파일입니다.");
		}
	}

	@Test
	public void cipherWithKeyString() {
		try {
			byte[] encrypted = LicenseMachine.issue(license, publicKey);
			FileUtil.makeFile(licensePath, encrypted);
			byte[] licenseByte = FileUtil.readFile(licensePath);
			boolean result = LicenseMachine.verify(licenseByte, privateKey);
			if (result) {
				logger.info("일치합니다.");
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

}
