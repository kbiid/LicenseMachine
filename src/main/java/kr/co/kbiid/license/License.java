package kr.co.kbiid.license;

import java.time.LocalDate;

/**
 * 라이선스의 정보(hostname, macAddress, 유효기간)를 담는다.
 * 
 * @author kbiid
 */
public class License {
	private String hostName;
	private String macAddress;
	private LocalDate expirationDate; // 유효 기간은 파일을 생성한 날짜로부터 1년

	public License(String hostName, String macAddress, LocalDate expirationDate) {
		this.hostName = hostName;
		this.macAddress = macAddress;
		this.expirationDate = expirationDate;
	}

	public String getHostName() {
		return hostName;
	}

	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	public String getMacAddress() {
		return macAddress;
	}

	public void setMacAddress(String macAddress) {
		this.macAddress = macAddress;
	}

	public LocalDate getExpirationDate() {
		return expirationDate;
	}

	public void setExpirationDate(LocalDate expirationDate) {
		this.expirationDate = expirationDate;
	}

	public String toStringWithDelimeter() {
		return String.format("%s|%s|%s", hostName, macAddress, expirationDate.toString());
	}

	@Override
	public String toString() {
		return String.format("License [hostName=%s, macAddress=%s, expirationDate=%s]", hostName, macAddress,
				expirationDate);
	}

}
