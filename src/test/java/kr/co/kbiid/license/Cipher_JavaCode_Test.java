package kr.co.kbiid.license;

import java.time.LocalDate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import kr.co.kbiid.license.util.FileUtil;
import kr.co.kbiid.license.util.HostInfoUtil;

public class Cipher_JavaCode_Test {

	private Log logger = LogFactory.getLog(Cipher_JavaCode_Test.class);

	private String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCY0OQzhKWdIwJEGNtRoTXrXaejgn9bttQ2joA6sRjf9NYHkwyU8zjWxaNi+JkIZXd/zDmcUae5NwPoXy8a0ewxbzdJUq7kt0hP0vvTldwEZEcnuxrYw9bUBpA6oS7bFFVWll0bejacfZzIKMz/zXt+ZKC1zHMblk42uiTbiDkdNwIDAQAB";
	private String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAJjQ5DOEpZ0jAkQY21GhNetdp6OCf1u21DaOgDqxGN/01geTDJTzONbFo2L4mQhld3/MOZxRp7k3A+hfLxrR7DFvN0lSruS3SE/S+9OV3ARkRye7GtjD1tQGkDqhLtsUVVaWXRt6Npx9nMgozP/Ne35koLXMcxuWTja6JNuIOR03AgMBAAECgYEAihC5DJ68rpLxuiqnBEJdn8/W5NDDVk6BvuTSj7Rvn+/p65/8zxpMcSbRLlsikEZ0R99w8X2Ixrsg6bINsfKVrMzFsHQ/ydLR4wp37rZ5Iabe/AV3PX/MUNf+WUTEc3WBYyrOnufObMGHULC0VuLIeGSaiyzL+ckKh11uwISJguECQQDtdrXTASVG5p5u8nuLheUfG+/eeq1FdAKnQymIKt2wuBhH6tzjQsSVyCxUivn0s1D/+Tv08Y5EaNyuPpURUe4nAkEApL6lmx1eKnD21oPKILCPnwawcntqcamlt2IgImlsRk9g0OEQ8/r0AR04ptxdnANopqp+peok5e11/m+BB5XScQJBALYmTBy6ET0Mo9UY/Xmt0G4HgPzYf1b6QRrKYu5Ha1wmKsHnv144FhGKxa5oGIoCjox7QumF7Qo+oaCq8q+heBsCQFYNHwN+u4j/qG80N4gLsXknTVL/FAJ60oyPPKm810mCfNeeN/S4yGsskELYKC0tuqQTukN/ofZXqqJUK9mCcIECQQDBocZQMx9sEtZdaP7U+Q4finPaCUlGP7D0aBWEJJiwkws1bhkNWmHSFyeimYnarsuNmsgXTWAjjcYx0Xo5xZ5w";

	private License license = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().plusYears(1));
	private License license_differentDate = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-92",
			LocalDate.now().minusMonths(1));
	private License license_differentMacAddress = new License(HostInfoUtil.getHostName(), "D8-C4-97-D6-5F-22",
			LocalDate.now().plusYears(1));
	private License license_differentHost = new License("kbiid", "D8-C4-97-D6-5F-92", LocalDate.now().plusYears(1));

	private String licensePath = "D:\\eclipse_workspace\\license-machine\\file\\license";
	private String differentDateLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\license_different_date";
	private String differentMacAddressLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\license_different_mac";
	private String differentHostPath = "D:\\eclipse_workspace\\license-machine\\file\\license_different_host";

	private String modulatedLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\license_modulate";
	private String overLengthLicensePath = "D:\\eclipse_workspace\\license-machine\\file\\license_over_length";

	@Test
	public void cipher() {
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

	@Test
	public void verifyOverLengthLicense() {

	}

	@Test
	public void verifyModulatedLicense() {

	}

	@Test
	public void differentDateLicense() {

	}

	@Test
	public void differentMacAddressLicense() {

	}

	@Test
	public void differentHostNameLicense() {

	}

	@Test
	public void encryptByPrivateAndDecryptByPublic() {

	}

}
