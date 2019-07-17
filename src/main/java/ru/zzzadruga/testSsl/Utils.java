package ru.zzzadruga.testSsl;

import java.io.InputStream;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class Utils {
    public static KeyStore loadKeyStore(String storeFilePath, char[] keyStorePwd) {
        KeyStore keyStore = null;

        try (InputStream in = Utils.class.getResourceAsStream("/" + storeFilePath)) {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in, keyStorePwd);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return keyStore;
    }

    public static SSLContext getSSLContext(String trustStoreName, char[] trustStorePassword,
        String keyStoreName, char[] keyStorePassword) throws Exception {
        KeyStore trustStore = loadKeyStore(trustStoreName, trustStorePassword);
        TrustManagerFactory tmf = TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        KeyStore keyStore = loadKeyStore(keyStoreName, keyStorePassword);
        KeyManagerFactory kmf = KeyManagerFactory
            .getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyStorePassword);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(),
            null);

        return ctx;
    }
}
