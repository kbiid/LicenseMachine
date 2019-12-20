package kr.co.kbiid.license.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class HostInfoUtil {

	private static Log logger = LogFactory.getLog(HostInfoUtil.class);

	public static String getHostName() {

		logger.info("getHostName..");
		String hostName = System.getenv("HOSTNAME");
		if (hostName != null) {
			return hostName;
		}

		String lineStr = "";
		try {
			Process process = Runtime.getRuntime().exec("hostname");
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			while ((lineStr = bufferedReader.readLine()) != null) {
				hostName = lineStr;
			}
		} catch (IOException e) {
			logger.error(e.getMessage());
			hostName = "";
		}
		return hostName;
	}

	public static List<String> getLocalMacAddresses() throws SocketException {

		logger.info("getLocalMacAddresses");
		List<String> macAddressList = new ArrayList<>();

		for (NetworkInterface network : IterableEnumeration.make(NetworkInterface.getNetworkInterfaces())) {
			byte[] mac = network.getHardwareAddress();
			if (mac != null) {
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < mac.length; i++) {
					sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
				}
				macAddressList.add(sb.toString());
			}
		}

		return macAddressList;
	}

}
