package kr.co.kbiid.license;

import java.io.File;
import java.time.LocalDate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.HostInfoUtil;

/*
java keytool로 만든 .jks파일로부터 추출된 키를 이용하여 암/복호화하는 테스트 케이스

선행 작업
1. javakeytool과 openssl로 생성한 publickey,privatekey의 경로를 확인하여 publicKeyPath,privateKeyPath변수에 저장한다.
2. 테스트 하고자 하는 라이선스의 정보를 License객체로 생성한다.
3. 라이선스가 유효하지 않은 경우를 테스트 하기 위하여 license_differentDate, license_differentMacAddress, license_differentHost를 각각 이름에 맞게 license의 내용과 다르게 설정하여 객체를 생성한다.

사용법
- 선행작업으로 설정된 변수들을 사용하여 테스트 코드들을 하나씩 실행시킨다.
- 실행 결과 라이선스 파일이 정상적으로 생성이 되는지 확인한다.
- license_modulated,license_over_length 같은 경우 정상적으로 생성된 license파일을 복사하여 이름을 수정하여 생성한 후 내용을 직접 수정한다.
*/
public class CipherJavaKeyToolTest {

	private static Log logger = LogFactory.getLog(CipherJavaKeyToolTest.class);
	
	private String publicKeyPath = "./file/keytool/public.pem";
	private String privateKeyPath = "./file/keytool/private.pem";

	private License license = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().plusYears(1));
	private License license_differentDate = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().minusMonths(1));
	private License license_differentMacAddress = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-22",
			LocalDate.now().plusYears(1));
	private License license_differentHost = new License("kbiid", "D8-C4-97-D6-5F-92", LocalDate.now().plusYears(1));

	private String licensePath = "./file/keytool/license";
	private String differentDateLicensePath = "./file/keytool/license_different_date";
	private String differentMacAddressLicensePath = "./file/keytool/license_different_mac";
	private String differentHostPath = "./file/keytool/license_different_host";

	private String modulatedLicensePath = "./file/keytool/license_modulated";
	private String overLengthLicensePath = "./file/keytool/license_over_length";

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
			e.printStackTrace();
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
				Assert.fail("유효하지 않은 라이센스입니다.");
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
				Assert.fail("유효하지 않은 라이센스입니다.");
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
