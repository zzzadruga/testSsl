package ru.zzzadruga.testSsl;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Objects;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import static ru.zzzadruga.testSsl.Utils.getSSLContext;
import static ru.zzzadruga.testSsl.Utils.loadKeyStore;

/**
 * Example from https://stackoverflow.com/questions/53323855/sslserversocket-and-certificate-setup/53325115
 */

public class TLSClient {
    public String request(InetAddress serverHost, int serverPort,
        String tlsVersion, String trustStoreName, char[] trustStorePassword,
        String keyStoreName, char[] keyStorePassword) throws Exception {

        Objects.requireNonNull(tlsVersion, "TLS version is mandatory");

        Objects.requireNonNull(serverHost, "Server host cannot be null");

        if (serverPort <= 0) {
            throw new IllegalArgumentException(
                "Server port cannot be less than or equal to 0");
        }

        SSLContext ctx = getSSLContext(trustStoreName, trustStorePassword, keyStoreName, keyStorePassword);

        SocketFactory factory = ctx.getSocketFactory();

        try (Socket connection = factory.createSocket(serverHost, serverPort)) {
            ((SSLSocket) connection).setEnabledProtocols(new String[] {tlsVersion});

            BufferedReader input = new BufferedReader(
                new InputStreamReader(connection.getInputStream()));
            return input.readLine();
        }
    }
}
