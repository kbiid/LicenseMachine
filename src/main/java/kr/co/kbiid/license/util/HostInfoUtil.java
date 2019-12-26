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
		
		// 시스템 환경변수 'HOSTNAME' 가져오기
		String hostName = System.getenv("HOSTNAME");
		if (hostName != null) {
			return hostName;
		}

		String lineStr = "";
		try {
			// hostname 명령어 실행
			Process process = Runtime.getRuntime().exec("hostname");
			
			// hostname 결과 읽어들이는 과정
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

		// 시스템 내 존재하는 모든 네트워크 디바이스의 리스트를 조회하여 물리주소를 가져오는 과정
		for (NetworkInterface network : IterableEnumeration.make(NetworkInterface.getNetworkInterfaces())) {
			// 물리주소 가져옴
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
