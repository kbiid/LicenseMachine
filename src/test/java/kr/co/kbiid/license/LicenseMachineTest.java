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

public class LicenseMachineTest {

	private static Log logger = LogFactory.getLog(LicenseMachineTest.class);

	private static License license;

	private String publicKeyString = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNTWeBhNN1Q7rSpK+Q4j7l5mh2MkYi29zg8fh0l2kmHQ+pDW1SNogWbHm11Zrb0WGKAJblRpiiS85mFcD0G8z1MPzYYGGywlqdXNS8YbxTgKcisN0H3dH1rvcRSkIpPGCV4iEfIrHnTlATdBaXCSV39kFT+X6H/bsKz2gza5/BWwIDAQAB";
	private String privateKeyString = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAI1NZ4GE03VDutKkr5DiPuXmaHYyRiLb3ODx+HSXaSYdD6kNbVI2iBZsebXVmtvRYYoAluVGmKJLzmYVwPQbzPUw/NhgYbLCWp1c1LxhvFOApyKw3Qfd0fWu9xFKQik8YJXiIR8isedOUBN0FpcJJXf2QVP5fof9uwrPaDNrn8FbAgMBAAECgYAJ7/SkjjPU3mOIJt7WAKNNxct47IY0M2QwSbQgdvmFHawZRoF2s7EUaqKQoCoY5XvHmc0C6NkZKN2mHkeIo1/hj3nbrtM85u5wR6Ws9GObnhcPL5MH4D/PIuZC6/vmJrlXRragesnpV+TQlZAe+PCukNiPUZDqxwojPJraf6+JYQJBANyGitdsT4udrCQp5sqsCOFt7goH6THmnOzDLiUbjbGzf801i7SGkXQZ0Z/m6Vs5pxYkVmJ7C642De5r8N/lfwsCQQCkCF+armsJOqAfgjLYEubTuuJpgBz9XRQRRkg4fWohAUpKIuLyEDkJP54QzPKpOBrGR047aMchT990gQDO0njxAkAD3Ar0CD5AKEtJ+r3CUE57e4wN+uN27x1R+3yEQ74wHP8gnU5Lo4tKJ+WGUelFonWtKoekg5jJvMJzqMn3cTHPAkBDfaKAjWVC7dk2PabX2qcY1NsVl33WDXcVSHqsq4WAQPylFkeUW3JsSL2roffyAkCZ9nrM3OaZ4ThKwk1ny5exAkBrbSPRMEx4PsWpmFdGUCDoAqZRdJHwvBuczWPS6KYr400lOcn9ViObmxzNJ4AvJBcftFpH+XaFEh/o9qisWS1M";

	private String licenseByteByPublicKeyString = "CRv9e6vTzwncPzrXtAF/zMrPgaE8yjjkWTtbNR6vz3Yu/0HeCWaAZui78RFslLcDD5iGsRFMq2hnBM6j+EMxVb/4ydNWoP3wybjTzDTGw/MksrcNpJjnbunwfi73kvU4x7BtH2O2MTnR97+HBmIMYKzH0R7Hzhmgvh01ZukvABg=";
	private String licenseByteByPrivateKeyString = "Y9eAXUzNCrX9Vp8Tv/jryT8JPd7jRTf3zNPwUbVCEpKGpeimXtOZcZL9ELmUlBO2+JIS9vriFsMTMqbJhhVyzcZEKyv5swTT2RWODgXoc+VzHF9H6cRIg+azaEBxc2KFQoREfarbKS1jKGHzxfTphaGoVKHsJAvGuhU7Si6A6uY=";

	private String publicKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\public_key.der";
	private String privateKeyPath = "D:\\eclipse_workspace\\license-machine\\file\\private_key.der";
	private String licensePath = "D:\\eclipse_workspace\\license-machine\\file\\license_test_keytool";

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
	public void testIssueLicenseString() throws Exception {
		byte[] licenseByte = LicenseMachine.issue(license, publicKeyString);
		logger.info(KeyUtil.toStringByBase64(licenseByte));
	}

	@Test
	public void testVerifyStringString() throws Exception {
		Assert.assertTrue(LicenseMachine.verify(licensePath, licensePath));
	}

	@Test
	public void testVerifyByteArrayString() throws Exception {
		Assert.assertTrue(
				LicenseMachine.verify(KeyUtil.toByteByBase64(licenseByteByPublicKeyString), privateKeyString));
	}

	@Test
	public void testIssueByPrivateLicenseFile() throws Exception {
		File file = new File(privateKeyPath);
		byte[] licenseByte = LicenseMachine.issueByPrivate(license, file);
		FileUtil.makeFile(licensePath, licenseByte);
		logger.info(KeyUtil.toStringByBase64(licenseByte));
	}

	@Test
	public void testIssueByPrivateLicenseString() throws Exception {
		byte[] licenseByte = LicenseMachine.issueByPrivate(license, privateKeyString);
		logger.info(KeyUtil.toStringByBase64(licenseByte));
	}

	@Test
	public void testVerifyByPublicStringString() throws Exception {
		Assert.assertTrue(LicenseMachine.verifyByPublic(licensePath, publicKeyPath));
	}

	@Test
	public void testVerifyByPublicByteArrayString() throws Exception {
		Assert.assertTrue(
				LicenseMachine.verifyByPublic(KeyUtil.toByteByBase64(licenseByteByPrivateKeyString), publicKeyString));
	}

}
