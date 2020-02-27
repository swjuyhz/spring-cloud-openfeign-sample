package com.zyh.consumer.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import feign.Client;

@Configuration
public class RkiServerFeignConfig {

	@Bean("rkiServerClient")
	public Client feignClient() {
		Client trustSSLSockets = new Client.Default(getSSLSocketFactory(), new NoopHostnameVerifier());
		return trustSSLSockets;
	}

	/*
	 * url = https://192.168.0.156:35449/rki path = /cert/1010120190115005229001.pfx
	 * pwd = 111111 partnerid = 1010120190115005229001 key =
	 * 0WjcblKhpCGs6PUUtrb03unjiJDuVPwC
	 */
	private static final String keyStorePath = "/cert/1010120190115005229001.pfx";
	private static final String password = "111111";

	public static InputStream readClassPathFile(String file) throws IOException {
		Resource resource = new ClassPathResource(file);
		InputStream is = resource.getInputStream();
		return is;
	}

	/**
	 * 获得KeyStore
	 *
	 * @param keyStorePath
	 * @param password
	 * @return
	 * @throws Exception
	 */
	public static KeyStore getKeyStore(InputStream is, String password, String type) throws Exception {
		KeyStore ks = KeyStore.getInstance(type);
		ks.load(is, password.toCharArray());
		is.close();
		return ks;
	}

	// 增加SSL
	public static SSLSocketFactory getSSLSocketFactory() {
		try {
			KeyStore keyStore = getKeyStore(readClassPathFile(keyStorePath), password, "PKCS12");
			SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(new TrustStrategy() {
				// 忽略掉对服务器端证书的校验
				@Override
				public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
					return true;
				}
			}).loadKeyMaterial(keyStore, password.toCharArray()).build();
			return sslContext.getSocketFactory();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
