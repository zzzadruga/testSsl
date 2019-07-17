package ru.zzzadruga.testSsl;

import javax.net.ssl.SSLHandshakeException;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static ru.zzzadruga.testSsl.TestUtils.hasCause;
import static ru.zzzadruga.testSsl.TestUtils.sslClientStart;
import static ru.zzzadruga.testSsl.TestUtils.sslServerStart;

public class TLSServerClientTest {
    @Test
    public void allCertificatesSignedAlphaCaTest() throws Exception {
        sslServerStart("login1-alpha.jks", "truststore-alpha.jks");

        assertEquals("valid",
            sslClientStart("login1-alpha.jks", "truststore-alpha.jks"));
    }

    @Test
    public void allCertificatesSignedDeltaCaTest() throws Exception {
        sslServerStart("login1-delta.jks", "truststore-delta.jks");

        assertEquals("valid",
            sslClientStart("login1-delta.jks", "truststore-delta.jks"));
    }

    @Test
    public void certificatesSignedDifferentCaButTruststoreIncludeAllCaTest() throws Exception {
        sslServerStart("login1-alpha.jks", "truststore-all.jks");

        assertEquals("valid",
            sslClientStart("login1-delta.jks", "truststore-all.jks"));
    }

    @Ignore
    @Test
    public void serverSignedAlphaCa_clientSignedDeltaCa_truststoreIncludeRootAndAlphaCa() {
        sslServerStart("login1-alpha.jks", "truststore-alpha.jks");

        // Expected SSLHandshakeException, but got java.net.ConnectException
        try {
            sslClientStart("login1-delta.jks", "truststore-alpha.jks");

            fail();
        }
        catch (Exception e) {
            assertTrue(hasCause(e, SSLHandshakeException.class));
        }
    }

    @Test
    public void serverSignedDeltaCa_clientSignedAlphaCa_truststoreIncludeRootAndAlphaCa() {
        sslServerStart("login1-delta.jks", "truststore-alpha.jks");

        try {
            sslClientStart("login1-alpha.jks", "truststore-alpha.jks");

            fail();
        }
        catch (Exception e) {
            assertTrue(hasCause(e, SSLHandshakeException.class));
        }
    }

    @Test
    public void unsignedClientCertificateTest() {
        sslServerStart("login1-alpha.jks", "truststore-alpha.jks");

        try {
            sslClientStart("unsigned.jks", "truststore-alpha.jks");

            fail();
        }
        catch (Exception e) {
            assertTrue(hasCause(e, SSLHandshakeException.class));
        }
    }

    @Test
    public void signedAnotherAlphaCaAndRootCaTest() {
        sslServerStart("login1-alpha.jks", "truststore-alpha.jks");

        try {
            sslClientStart("login1-sigma.jks", "truststore-alpha.jks");

            fail();
        }
        catch (Exception e) {
            assertTrue(hasCause(e, SSLHandshakeException.class));
        }
    }

    @Ignore
    @Test
    public void expiredClientCertificateTest() throws Exception {
        sslServerStart("login1-alpha-expired.jks", "truststore-alpha.jks");

        // Expected SSLHandshakeException, but got java.net.ConnectException
        try {
            sslClientStart("login1-alpha-expired.jks", "truststore-alpha.jks");

            fail();
        }
        catch (Exception e) {
            assertTrue(hasCause(e, SSLHandshakeException.class));
        }
    }
}
