package kr.co.kbiid.license;

import java.io.File;
import java.time.LocalDate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.HostInfoUtil;

/**
 * openssl을 이용하여 생성된 키를 사용하여 암/복호화하는 테스트 케이스
 *
 * 선행 작업 
 * 1. openssl이 설치되어있는지 확인한 후, 설치되어 있지 않다면 설치한다.
 * 2. openssl로 생성한 publickey,privatekey의 경로를 확인하여 publicKeyPath,privateKeyPath변수에 저장한다.
 * 3. 테스트 하고자 하는 라이선스의 정보를 License객체로 생성한다.
 * 4. 라이선스가 유효하지 않은 경우를 테스트 하기 위하여 license_differentDate, license_differentMacAddress, license_differentHost를 각각 이름에 맞게 license의 내용과 다르게 설정하여 객체를 생성한다.
 *
 * 사용법
 * - 선행작업으로 설정된 변수들을 사용하여 테스트 코드들을 하나씩 실행시킨다.
 * - 실행 결과 라이선스 파일이 정상적으로 생성이 되는지 확인한다.
 * - license_modulated,license_over_length 같은 경우 정상적으로 생성된 license파일을 복사하여 이름을 수정하여 생성한 후 내용을 직접 수정한다.
 *
 */
public class Cipher_Openssl_Test {

	private static Log logger = LogFactory.getLog(Cipher_Openssl_Test.class);

	private String publicKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\public_key.der";
	private String privateKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\private_key.der";

	private License license = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().plusYears(1));
	private License license_differentDate = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().minusMonths(1));
	private License license_differentMacAddress = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-22",
			LocalDate.now().plusYears(1));
	private License license_differentHost = new License("kbiid", "D8-C4-97-D6-5F-92", LocalDate.now().plusYears(1));

	private String licensePath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\license";
	private String differentDateLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\license_different_date";
	private String differentMacAddressLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\license_different_mac";
	private String differentHostPath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\license_different_host";

	private String modulatedLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\license_modulated";
	private String overLengthLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\license_over_length";

	@Test
	public void cipher() {
		try {
			File file = new File(publicKeyPath);
			byte[] encrypted = LicenseMachine.issue(license, file);
			FileUtil.makeFile(licensePath, encrypted);
			boolean result = LicenseMachine.verify(licensePath, privateKeyPath);
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
	public void verifyOverLengthLicense() {
		try {
			boolean result = LicenseMachine.verify(overLengthLicensePath, privateKeyPath);
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
			boolean result = LicenseMachine.verify(modulatedLicensePath, privateKeyPath);
			if (result) {
				logger.info("일치합니다.");
			} else {
				Assert.fail("일치하지 않습니다.");
			}
		} catch (Exception e) {
			e.printStackTrace();
			logger.error(e.getMessage());
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void differentDateLicense() {
		try {
			File file = new File(publicKeyPath);
			byte[] encrypted = LicenseMachine.issue(license_differentDate, file);
			FileUtil.makeFile(differentDateLicensePath, encrypted);
			boolean result = LicenseMachine.verify(differentDateLicensePath, privateKeyPath);
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
			File file = new File(publicKeyPath);
			byte[] encrypted = LicenseMachine.issue(license_differentMacAddress, file);
			FileUtil.makeFile(differentMacAddressLicensePath, encrypted);
			boolean result = LicenseMachine.verify(differentMacAddressLicensePath, privateKeyPath);
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
			File file = new File(publicKeyPath);
			byte[] encrypted = LicenseMachine.issue(license_differentHost, file);
			FileUtil.makeFile(differentHostPath, encrypted);
			boolean result = LicenseMachine.verify(differentHostPath, privateKeyPath);
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
			File file = new File(privateKeyPath);
			byte[] encrypted = LicenseMachine.issueByPrivate(license, file);
			FileUtil.makeFile(licensePath, encrypted);
			boolean result = LicenseMachine.verifyByPublic(licensePath, publicKeyPath);
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
