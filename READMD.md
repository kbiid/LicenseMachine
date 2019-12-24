#License Machine

### 정의
 * 라이선스 정보(HostName, Mac Address, 유효 기간)를 암/복호화, 파일 생성 및 읽기가 가능한 API

## 사용법
* 자세한 사용법은 테스트 케이스의 코드를 참고한다.
* 개인키로 암호화, 공개키로 복호화 하는 경우에도 사용법은 동일하다.

##### 암호화  
* 키를 파일로 관리하지 않을 경우  

	- KeyUtil의 genRSAKeyPair라는 메소드를 사용하여 KeyPair를 생성 후 Private Key, Public Key의 정보를 얻는다.
	- 만들고자 하는 라이선스의 정보를 토대로 라이선스 객체를 생성한다.
	- LicenseMachine의 issue 메서드를 사용(라이선스 객체와 공개키를 입력)하여 암호화된 결과값(byte 배열)을 얻는다.
	- FileUtil의 makeFile 메서드를 사용하여 라이선스 파일을 생성한다. makeFile메서드에는 라이선스를 저장할 경로가 문자열, 라이선스 암호화 결과값을 입력한다.
	- 파일이 정상적으로 생성이 되었는지 확인한다.
* 키를 파일로 관리하는 경우  

	- 공개 키가 저장되어 있는 경로를 입력하여 File객체를 생성한다.
	- 만들고자 하는 라이선스의 정보를 토대로 라이선스 객체를 생성한다.
	- LicenseMachine의 issue 메서드를 사용(라이선스 객체와 File 객체를 입력)하여 암호화된 결과값(byte 배열)을 얻는다.
	- FileUtil의 makeFile 메서드를 사용하여 라이선스 파일을 생성한다. makeFile메서드에는 라이선스를 저장할 경로가 들어있는 문자열, 라이선스 암호화 결과값을 입력한다.
	- 파일이 정상적으로 생성이 되었는지 확인한다.
 
##### 복호화
* 키를 파일로 관리하지 않을 경우  

	- FileUtil의 readFile 메서드를 사용하여 라이선스 파일을 읽어온다. 결과값으로 라이선스 파일의 내용(byte 배열)을 얻는다. readFile메서드에는 라이선스 파일이 들어있는 경로를  입력한다.
	- LicenseMachine의 verify메서드를 이용하여 라이선스가 유효한지 검증 후 결과를 얻는다. 유효할 경우 true, 유효하지 않을 경우 false를 리턴한다. verify메서드에는 라이선스 파일에서 얻은 값과 개인키를 입력한다.
* 키를 파일로 관리하는 경우  

	- FileUtil의 readFile 메서드를 사용하여 라이선스 파일을 읽어온다. 결과값으로 라이선스 파일의 내용(byte 배열)을 얻는다. readFile메서에는 라이선스 파일이 들어있는 경로를 입력한다.
	- LicenseMachine의 verify메서드를 이용하여 라이선스가 유효한지 검증 후 결과를 얻는다. 유효할 경우 true, 유효하지 않을 경우 false를 리턴한다. verify메서드에는 라이선스 파일의 경로와 개인키 파일의 경로를 입력한다. 

# TroubleShooting
* pem파일을 읽어들였는데 Invalid Key Format에러가 날 경우  

	pem파일의 내용을 확인하여 '---BEGIN'문자열 전에 다른 내용이 있을 경우 이전 내용을 제거 후 실행한다.