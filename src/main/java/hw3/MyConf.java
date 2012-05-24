package hw3;

import java.io.FileInputStream;

import java.io.IOException;
import java.util.Properties;

/*
 * You do not have to change anything here.
 */

/**
 * Configuration manager.
 * 
 * You will need to prepare configuration file that this configuration manager will read.
 * Configuration file example:
 * 
 * <pre>
 *   javax.net.ssl.keyStore=server.jks
 *   javax.net.ssl.keyStorePassword=secret
 *   my.cerver.certificate=server.crt
 *   my.cerver.key=priv.key
 * </pre>
 * 
 * Run {@code MyConf#load()} to load properties from default configuration file (hw3.properties).
 * After that, you can access configuration properties as {@code System#getProperty(String)}
 * in your code, example:
 * 
 * <pre>
 *   String certificateFilePath = System.getProperty("my.server.certificate")
 * </pre>
 */
public abstract class MyConf {
	public static final void load() throws IOException {
		load("hw3.properties");
	}

	public static final void load(String filePath) throws IOException {
		System.out.println(" * Reading config properties from " + filePath + "...");
		Properties properties = new Properties();
		properties.load(new FileInputStream(filePath));
		properties.putAll(System.getProperties());
		System.setProperties(properties);
	}
}
