package ru.zzzadruga.testSsl;

import com.sun.istack.internal.Nullable;
import java.net.InetAddress;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

public class TestUtils {
    public static final AtomicInteger SERVER_PORT = new AtomicInteger(8000);
    private static final String TLS_VERSION = "TLSv1.2";
    private static final int SERVER_COUNT = 1;
    public static final String SERVER_HOST_NAME = "127.0.0.1";
    public static final char[] DFLT_PSWRD = new char[] {'1', '2', '3', '4',
        '5', '6'};
    public static final String DIR = "certs/";
    public static Future serverFuture;

    public static void sslServerStart(String keyStore, String trustStore) {
        TLSServer server = new TLSServer();

        ExecutorService serverExecutor = Executors.newFixedThreadPool(SERVER_COUNT);
        serverExecutor.submit(() -> {
            try {
                server.serve(SERVER_PORT.get(), TLS_VERSION, DIR + trustStore,
                    DFLT_PSWRD, DIR + keyStore, DFLT_PSWRD);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    public static String sslClientStart(String keyStore, String trustStore) throws Exception {

        TLSClient client = new TLSClient();

        try {
            return client.request(
                InetAddress.getByName(SERVER_HOST_NAME), SERVER_PORT.get(), TLS_VERSION,
                DIR + trustStore, DFLT_PSWRD, DIR + keyStore, DFLT_PSWRD);
        } catch (Exception e) {

            e.printStackTrace();

            throw e;
        }
    }

    public static boolean hasCause(@Nullable Throwable t, @Nullable Class<?>... cls) {
        if (t == null || cls == null || cls.length == 0)
            return false;

        assert cls != null;

        for (Throwable th = t; th != null; th = th.getCause()) {
            for (Class<?> c : cls) {
                if (c.isAssignableFrom(th.getClass()))
                    return true;
            }

            for (Throwable n : th.getSuppressed()) {
                if (hasCause(n, cls))
                    return true;
            }

            if (th.getCause() == th)
                break;
        }

        return false;
    }

    public static int certsCount(KeyStore keyStore){
        int count = 0;

        try {
            Enumeration<String> certs = keyStore.aliases();

            while (certs.hasMoreElements()) {
                certs.nextElement();

                count++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return count;
    }
}