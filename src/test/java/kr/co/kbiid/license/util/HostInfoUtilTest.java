package kr.co.kbiid.license.util;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import kr.co.kbiid.license.util.HostInfoUtil;

public class HostInfoUtilTest {

	private static Log logger = LogFactory.getLog(HostInfoUtilTest.class);
	
	@Test
	public void testGetHostName() {
		String hostName = HostInfoUtil.getHostName();
		logger.info(hostName);
	}

	@Test
	public void testGetLocalMacAddresses() throws Exception {
		List<String> localMacAddresses = HostInfoUtil.getLocalMacAddresses();
		for (String string : localMacAddresses) {
			logger.info(string);
		}
	}

}
