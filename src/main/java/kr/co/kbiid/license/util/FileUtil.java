package kr.co.kbiid.license.util;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;

public class FileUtil {

	public static void makeFile(String fileFullPath, byte[] data) throws IOException, NullPointerException {
		FileUtils.writeByteArrayToFile(new File(fileFullPath), data);
	}

	public static byte[] readFile(String fileFullPath) throws IOException, NullPointerException {
		File file = new File(fileFullPath);
		return FileUtils.readFileToByteArray(file);
	}

}
