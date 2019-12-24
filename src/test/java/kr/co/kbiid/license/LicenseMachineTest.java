package kr.co.kbiid.license;

import java.io.File;
import java.time.LocalDate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.HostInfoUtil;
import kr.co.kbiid.license.util.KeyUtil;

/**
 *
 * 선행 작업 
 * 1. keyUtilTest.java에서 genRSAKeyPair로 publicKey와 privateKey를 생성한 후 값을 확인하여 아래의 publicKey,privateKey 변수에 값을 저장한다.
 * 2. 테스트 하고자 하는 라이선스의 정보를 License객체로 생성한다.
 * 3. publicKeyPath, privateKeyPath는 키를 생성하여 키가 있는 경로를 저장한다.
 * 4. licensePath는 라이선스를 저장할 위치를 저장한다.
 *
 * 사용법
 * - 선행작업으로 설정된 변수들을 사용하여 테스트 코드들을 하나씩 실행시킨다.
 * - 실행 결과 라이선스 파일이 정상적으로 생성이 되는지 확인한다.
 * - licenseByteByPublicKey,licenseByteByPrivateKey의 변수값은 testIssueLicenseString,testIssueByPrivateLicenseFile에서 확인할 수 있다.
 * - license_modulated,license_over_length 같은 경우 정상적으로 생성된 license파일을 복사하여 이름을 수정하여 생성한 후 내용을 직접 수정한다.
 */
public class LicenseMachineTest {

	private static Log logger = LogFactory.getLog(LicenseMachineTest.class);

	private static License license;

	private String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBRkxnQcVf05n2tLgc+Yw88KvxZFu7WrLHRmQuEt/fPl+amwkfwcMSugEqFrMWwZ4kH8zwFhnQvCLdrBwCKuosLzcvq3E498glCjabdIea68LgQkN2Trg3HXbxO57lsOsCUjawu78I3fuTUiJaSXKTPGPVAQJlhZzpN3gld4PmiQIDAQAB";
	private String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMFGTGdBxV/Tmfa0uBz5jDzwq/FkW7tassdGZC4S398+X5qbCR/BwxK6ASoWsxbBniQfzPAWGdC8It2sHAIq6iwvNy+rcTj3yCUKNpt0h5rrwuBCQ3ZOuDcddvE7nuWw6wJSNrC7vwjd+5NSIlpJcpM8Y9UBAmWFnOk3eCV3g+aJAgMBAAECgYAn47BlJ0frLSr7pfTR1hdBhJKYMZRVKLT5N+f5MmAOHTtyF0lcyorOVKFk5GZ17eQLpJyReJ4/XHT9t0XYlK7br9XO99DKVz2tLM4q3yEgDMzXHIJHAv0GSRnHQLmvyNH1mEZn3QInfxNKqgBlxsIClmkQXaBY3SmOZaqQHeTGuQJBAOJ9MI+sHL8wIG5vCxVrYUUkmn9KuzOXRS3fRoMfT23FiW03519mkhm55GYLuK+nqEhss5M4HQv3AqaxhpNHLX8CQQDadTPOl5uiPcS9yLSl5T2DZek5KQpYo6CgD+GiynNaKnYDZCeDJQMaNLRi7UMZBUyueUrdZ74OU6eEYTduO3/3AkEAnDTbmTuLWBFJTOEpM8yreZSVOdXA5wQdolWrvCOMFJl4/urfmNyVR0j+TaMn7X4kgk72S0MYRXhHS9CEkG824QJBAMvyn2tAHwxYnlSQDBbU7Zi+i/3RUtdt64eDTCOu3gJPod2Io1rMMxlEGyRAXWP+jphUpJAPSmAVuU7dc+J1qgECQQCjKsr5cmK8QkPwb/FSeuoGfwIB8HPD8K6q7fozmIibOFtFhkys/sqVZUptstYK18dmUlviKasHGhOeuKwV3IoQ";

	private String licenseByteByPublicKey = "rLcH2CufRoNfZRmJxWkMQm+baU2wQkKuBuyCAn2MMcghwGeA8N293b6PsaNRasfbyO8F9kqPPRC4TQzP0PfJYVmefu8E3Ft6mqIIQa4yAYgtti7w81D7FgqkmD8Ll6iTMfnieHuWHgOMqNSuihFVTF4/stw9XMGFk5iQpiDVLVY=";
	private String licenseByteByPrivateKey = "ENzMvA5wrGNPacXiZn6m+eeoTQ41+UGh2/TfhL79DU0qyRzm0HBPfZTmahWjwYXss65YttzzvLItrvXJ2MCOq5JDO2K40DQuulcfeW6GJtGi3vxZS+zBMlyLtsiJsCLt9fyHIRTLZWWcKCyr1NfINHXOUbisuEu7Yi2FMHbH1p0=";

	private String publicKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\public_key.der";
	private String privateKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\openssl\\private_key.der";
	private String licensePath = "D:\\eclipse_workspace\\license-machine\\file\\license";

	@BeforeClass
	public static void setUp() {
		license = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92", LocalDate.now().plusYears(1));
	}

	@Test
	public void testIssueLicenseFile() throws Exception {
		File file = new File(publicKeyPath);
		byte[] licenseByte = LicenseMachine.issue(license, file);
		FileUtil.makeFile(licensePath, licenseByte);
		logger.info(KeyUtil.toStringByBase64(licenseByte));
	}

	@Test
	public void testVerifyStringString() throws Exception {
		Assert.assertTrue(LicenseMachine.verify(licensePath, privateKeyPath));
	}
	
	@Test
	public void testIssueLicenseString() throws Exception {
		byte[] licenseByte = LicenseMachine.issue(license, publicKey);
		logger.info(KeyUtil.toStringByBase64(licenseByte));
	}

	@Test
	public void testVerifyByteArrayString() throws Exception {
		Assert.assertTrue(
				LicenseMachine.verify(KeyUtil.toByteByBase64(licenseByteByPublicKey), privateKey));
	}

	@Test
	public void testIssueByPrivateLicenseFile() throws Exception {
		File file = new File(privateKeyPath);
		byte[] licenseByte = LicenseMachine.issueByPrivate(license, file);
		FileUtil.makeFile(licensePath, licenseByte);
		logger.info(KeyUtil.toStringByBase64(licenseByte));
	}
	
	@Test
	public void testVerifyByPublicStringString() throws Exception {
		Assert.assertTrue(LicenseMachine.verifyByPublic(licensePath, publicKeyPath));
	}

	@Test
	public void testIssueByPrivateLicenseString() throws Exception {
		byte[] licenseByte = LicenseMachine.issueByPrivate(license, privateKey);
		logger.info(KeyUtil.toStringByBase64(licenseByte));
	}

	@Test
	public void testVerifyByPublicByteArrayString() throws Exception {
		Assert.assertTrue(LicenseMachine.verifyByPublic(KeyUtil.toByteByBase64(licenseByteByPrivateKey), publicKey));
	}

}
