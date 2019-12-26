# License Machine

## 정의
* 라이선스 정보(HostName, Mac Address, 유효 기간)를 암/복호화, 파일 생성 및 읽기가 가능한 API

## 사용법
* 자세한 사용법은 테스트 케이스의 코드를 참고한다.

### LicenseMachine  
#### issue
* issue(License, PublicKeyFile)

```java
License license = new License("호스트", "Z0-H1-12-B7-9V-10", LocalDate.now().plusYears(1));
File file = new File(publicKeyPath); 
LicenseMachine.issue(license, file);
```
* issue(License, publicKeyString)

```java
License license = new License("호스트", "Z0-H1-12-B7-9V-10", LocalDate.now().plusYears(1));
LicenseMachine.issue(license, publicKeyString);
```
* issueByPrivate(License, privateKeyFile)

```java
License license = new License("호스트", "Z0-H1-12-B7-9V-10", LocalDate.now().plusYears(1));
File file = new File(privateKeyFile); 
LicenseMachine.issue(license, file);
```
* issue(License, privateKeyString)

```java
License license = new License("호스트", "Z0-H1-12-B7-9V-10", LocalDate.now().plusYears(1));
LicenseMachine.issue(license, privateKeyString);
```

#### verify
* verify(LicensePath, privateKeyPath)

```java
LicenseMachine.verify(licensePath, privateKeyPath)
```
* verify(encrypted, privateKeyString)

```java
LicenseMachine.verify(KeyUtil.toByteByBase64(encrypted), privateKey)
```
* verifyByPublic(LicensePath, publicKeyPath)

```java
LicenseMachine.verifyByPublic(licensePath, publicKeyPath)
```
* verifyByPublic(encrypted, publicKeyString)

```java
LicenseMachine.verifyByPublic(KeyUtil.toByteByBase64(encrypted), publicKeyString)
```

## TroubleShooting
* pem파일을 읽어들였는데 Invalid Key Format에러가 날 경우  

	pem파일의 내용을 확인하여 '---BEGIN'문자열 전에 다른 내용이 있을 경우 이전 내용을 제거 후 실행한다.