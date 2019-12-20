package kr.co.kbiid.license;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Test;

import kr.co.kbiid.license.util.KeyUtil;

public class KeyUtilTest {

	private static Log logger = LogFactory.getLog(KeyUtilTest.class);

	String privateKeyFromFile = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0fXwq3wHTXdHM7JtS4iuKNoYTcAj+M6XQU14jP/qIOD3tEN5JY8uQVvqS4DIol2cSL+nBE9+eCdyFj60sDvw0R//awEz8vPySUcI1wZ+7+9/reVyeTm+DfMvwteLPa49UgghtDHzPlz3H3v0ZR65RLQ3oFop3orVC81Xb7MA9/W71Bj9JyPj31CrkprSQwd8s0GuIHbXjkoDK2orUe5b7LEwrDyNmKVRG5kFtZo3c971d8OWmwxDEqCoLs3YSr9h8oh18e5is4T3ByuSjWp/aL9GCxKtJZaDuV8EVChmKfrsJOVDVu8pY5RiJ/ddO+C8F6S/wDuYWj4nlTg1A4A3lAgMBAAECggEADCaWgVxaBxy9zwnuuvm27KsXA5/7OwHHG+tA3yajeyAuKxODo3Uwcxsn61NkjQ8ERVksZ28rEryfN+6gPeMUX4CpXNStWiZu6nrOlEfgtQsT3ApjjdTB9RwlrqLQDh6zm4DViGHa1S7dXeNJLraAqb5avVEnKT6u7T7sfM3Hc2TLX9E/bVjUeaE4eTHcRf6/QCqZ9ypiF3QGtzZP0cmQAdi4D/iTPdprgOuOYRkZQhBnvpg26ay4fWjx79xjaz//Neut7VLq5YFAAHa+0xeRCyL9Hkyhi6mDpBI3iIEw4STj0AQ7daMLNI+MUaNL1AJVM1d0hjLki3DqarMBNdg1UQKBgQDkzefBx9whAzGFK0Np+qFSvFKHpg+q3fTYNqS8k4WfpSmLVjfPtwahtOJmuojsrprStzlRliRM9yy8DGumCUiPEThXwJ6s6tgILqmH0EWAIdHbFXS/w+KPiS919ZF+aVWLMMvmLNRc7Kh5u0wWCQq75Z8N+8lskNCt5jRQQujc4wKBgQDJ8XgfW9jHGiLfm4tbxREoeEaHLMTcQ7G5kOa3vB9oKwf7DArlwzs4hu3Ykmcf9ALCUypgqZdxv+/6mX0BB5SibroV+vGQhTgBQQqonN2lP+iCErGkBPx+YzFeOpWJlkQN6DUMUjAGKe4fFjOkiKUyvSWznQmq0rdTFUySeDJslwKBgQC1OdYYaboUt9fQV80ksyx2QM3JvaFpQDa/zsA60Uokgghe4eKA9sIc8Q3mOldbyIy+2/tdgOOtxpW7OMdHEtFS6FvNPbcw1S5ZhMQo27FA5Qi4U81OWtQnxow+DUy5aKsl/XdzEA0AsT5cdRq11WGYJC8QP19yS13Ob6j97ZFN6wKBgQCK0YYMsHuNKodMhUVAGXDZDA0XgQv2ikZS1Kv1I8nHNsVuqvGWziUYj5BSrxla2sdGxBq+hfZISHP0JazLl2VyX4Fl+LIz8Y/1NLvZ+rNWlF8Fg0pAAPl8/D0ElGsVQImZscU9qgW/RvWcwwtPEGvXPDT9incJyX4iC+MuUJgBEwKBgAHwxdTi/vXUaiLINaivw0kEC7IKPyGoArov+RHc1cd5a61/f5LsoY69qFC8/46oamZcrhpSgi0zEhWanMS1aaHCeDjz6dqPyY70wp74N7p3+05KcTu/pEWfHD6sqVEFQylWxiWO3GnaEXsMtmkF+CAp95VmWcVew5FMpWceP9se";
	String publicKeyFromFile = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtH18Kt8B013RzOybUuIrijaGE3AI/jOl0FNeIz/6iDg97RDeSWPLkFb6kuAyKJdnEi/pwRPfngnchY+tLA78NEf/2sBM/Lz8klHCNcGfu/vf63lcnk5vg3zL8LXiz2uPVIIIbQx8z5c9x979GUeuUS0N6BaKd6K1QvNV2+zAPf1u9QY/Scj499Qq5Ka0kMHfLNBriB2145KAytqK1HuW+yxMKw8jZilURuZBbWaN3Pe9XfDlpsMQxKgqC7N2Eq/YfKIdfHuYrOE9wcrko1qf2i/RgsSrSWWg7lfBFQoZin67CTlQ1bvKWOUYif3XTvgvBekv8A7mFo+J5U4NQOAN5QIDAQAB";
	String privateKeyFromApp = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAI1NZ4GE03VDutKkr5DiPuXmaHYyRiLb3ODx+HSXaSYdD6kNbVI2iBZsebXVmtvRYYoAluVGmKJLzmYVwPQbzPUw/NhgYbLCWp1c1LxhvFOApyKw3Qfd0fWu9xFKQik8YJXiIR8isedOUBN0FpcJJXf2QVP5fof9uwrPaDNrn8FbAgMBAAECgYAJ7/SkjjPU3mOIJt7WAKNNxct47IY0M2QwSbQgdvmFHawZRoF2s7EUaqKQoCoY5XvHmc0C6NkZKN2mHkeIo1/hj3nbrtM85u5wR6Ws9GObnhcPL5MH4D/PIuZC6/vmJrlXRragesnpV+TQlZAe+PCukNiPUZDqxwojPJraf6+JYQJBANyGitdsT4udrCQp5sqsCOFt7goH6THmnOzDLiUbjbGzf801i7SGkXQZ0Z/m6Vs5pxYkVmJ7C642De5r8N/lfwsCQQCkCF+armsJOqAfgjLYEubTuuJpgBz9XRQRRkg4fWohAUpKIuLyEDkJP54QzPKpOBrGR047aMchT990gQDO0njxAkAD3Ar0CD5AKEtJ+r3CUE57e4wN+uN27x1R+3yEQ74wHP8gnU5Lo4tKJ+WGUelFonWtKoekg5jJvMJzqMn3cTHPAkBDfaKAjWVC7dk2PabX2qcY1NsVl33WDXcVSHqsq4WAQPylFkeUW3JsSL2roffyAkCZ9nrM3OaZ4ThKwk1ny5exAkBrbSPRMEx4PsWpmFdGUCDoAqZRdJHwvBuczWPS6KYr400lOcn9ViObmxzNJ4AvJBcftFpH+XaFEh/o9qisWS1M";
	String publicKeyFromApp = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNTWeBhNN1Q7rSpK+Q4j7l5mh2MkYi29zg8fh0l2kmHQ+pDW1SNogWbHm11Zrb0WGKAJblRpiiS85mFcD0G8z1MPzYYGGywlqdXNS8YbxTgKcisN0H3dH1rvcRSkIpPGCV4iEfIrHnTlATdBaXCSV39kFT+X6H/bsKz2gza5/BWwIDAQAB";

	@Test
	public void genRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = KeyUtil.genRSAKeyPair();

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		logger.info("publicKey : " + KeyUtil.toStringByBase64(publicKey.getEncoded()));
		logger.info("privateKey : " + KeyUtil.toStringByBase64(privateKey.getEncoded()));
	}

	@Test
	public void getPrivateKeyByFile() throws Exception {
		PrivateKey privateKey = KeyUtil
				.getPrivateKeyByFile("D:\\eclipse_workspace\\LicenseMachine\\file\\private_key.der");
		logger.info(KeyUtil.toStringByBase64(privateKey.getEncoded()));
	}

	@Test
	public void getPrivateKeyByString() throws Exception {
		PrivateKey privateKey = KeyUtil.getPrivateKeyByString(privateKeyFromApp);
		logger.info(KeyUtil.toStringByBase64(privateKey.getEncoded()));
	}

	@Test
	public void getPublicKeyByFile() throws Exception {
		PublicKey publicKey = KeyUtil.getPublicKeyByFile("D:\\eclipse_workspace\\LicenseMachine\\file\\public_key.der");
		logger.info(KeyUtil.toStringByBase64(publicKey.getEncoded()));
	}
	
	@Test
	public void getPublicKeyByString() throws Exception {
		PublicKey publicKey = KeyUtil.getPublicKeyByString(publicKeyFromApp);
		Assert.assertNotNull(publicKey);
	}


}
