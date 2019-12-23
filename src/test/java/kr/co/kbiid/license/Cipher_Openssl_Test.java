package kr.co.kbiid.license;

import java.io.File;
import java.time.LocalDate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.HostInfoUtil;

public class Cipher_Openssl_Test {

	private static Log logger = LogFactory.getLog(Cipher_Openssl_Test.class);

	private String publicKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\public_key.pem";
	private String privateKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\private_key.pem";

	private License license = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().plusYears(1));
	private License license2 = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().minusMonths(1));
	
	private String licensePath = "D:\\eclipse_workspace\\license-machine\\file\\license";
	private String licensePath2 = "D:\\eclipse_workspace\\license-machine\\file\\license2";
	
	private String modulatedLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\license_modulate";
	
	@Test
	public void cipherWithKeyFileSuccess() {
		logger.info("cipherWithKeyFileSuccess start..");
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
		logger.info("cipherWithKeyFileLicenseModulated start..");
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
		logger.info("cipherWithKeyFileHostInfoDifferent start..");
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
			Assert.fail("잘못된 라이센스 파일입니다.");
		}
	}

}
