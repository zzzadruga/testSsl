package ru.zzzadruga.testSsl;

import java.io.InputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import static ru.zzzadruga.testSsl.Utils.getSSLContext;
import static ru.zzzadruga.testSsl.Utils.loadKeyStore;

/**
 * Example from https://stackoverflow.com/questions/53323855/sslserversocket-and-certificate-setup/53325115
 */


public class TLSServer {
    public void serve(int port, String tlsVersion, String trustStoreName,
        char[] trustStorePassword, String keyStoreName, char[] keyStorePassword)
        throws Exception {

        Objects.requireNonNull(tlsVersion, "TLS version is mandatory");

        if (port <= 0) {
            throw new IllegalArgumentException(
                "Port number cannot be less than or equal to 0");
        }

        SSLContext ctx = getSSLContext(trustStoreName, trustStorePassword, keyStoreName, keyStorePassword);

        SSLServerSocketFactory factory = ctx.getServerSocketFactory();

        try (ServerSocket listener = factory.createServerSocket(port)) {
            SSLServerSocket sslListener = (SSLServerSocket)listener;

            sslListener.setNeedClientAuth(true);
            sslListener.setEnabledProtocols(new String[] {tlsVersion});

            try (Socket socket = sslListener.accept()) {
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                out.println("valid");
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

    }
}