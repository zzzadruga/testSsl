package ru.zzzadruga.testSsl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static ru.zzzadruga.testSsl.TestUtils.DFLT_PSWRD;
import static ru.zzzadruga.testSsl.TestUtils.certsCount;
import static ru.zzzadruga.testSsl.TestUtils.hasCause;
import static ru.zzzadruga.testSsl.Utils.loadKeyStore;

public class CertificateCheckTest {
    @Test
    public void checkCertificates() throws KeyStoreException {
        KeyStore truststoreAll = loadKeyStore("certs/truststore-all.jks", DFLT_PSWRD);
        KeyStore truststoreAlpha = loadKeyStore("certs/truststore-alpha.jks", DFLT_PSWRD);
        KeyStore truststoreDelta = loadKeyStore("certs/truststore-delta.jks", DFLT_PSWRD);

        String rootCaAlias = "one";
        String intermediateCaAlphaAlias = "alpha";
        String intermediateCaDeltaAlias = "delta";

        X509Certificate rootCa = (X509Certificate)truststoreAll.getCertificate(rootCaAlias);
        X509Certificate intermediateCaAlpha = (X509Certificate)truststoreAll.getCertificate(intermediateCaAlphaAlias);
        X509Certificate intermediateCaDelta = (X509Certificate)truststoreAll.getCertificate(intermediateCaDeltaAlias);

        assertEquals(rootCa, truststoreAlpha.getCertificate(rootCaAlias));
        assertEquals(intermediateCaAlpha, truststoreAlpha.getCertificate(intermediateCaAlphaAlias));

        assertEquals(rootCa, truststoreDelta.getCertificate(rootCaAlias));
        assertEquals(intermediateCaDelta, truststoreDelta.getCertificate(intermediateCaDeltaAlias));

        assertEquals(certsCount(truststoreAll), 3);
        assertEquals(certsCount(truststoreAlpha), 2);
        assertEquals(certsCount(truststoreDelta), 2);

        assertEquals(intermediateCaAlpha.getIssuerDN(), intermediateCaDelta.getIssuerDN());
        assertEquals(intermediateCaAlpha.getIssuerDN(), rootCa.getSubjectDN());

        KeyStore login1Alpha = loadKeyStore("certs/login1-alpha.jks", DFLT_PSWRD);
        KeyStore login1Delta = loadKeyStore("certs/login1-delta.jks", DFLT_PSWRD);
        KeyStore login1AlphaExpired = loadKeyStore("certs/login1-alpha-expired.jks", DFLT_PSWRD);
        KeyStore unsigned = loadKeyStore("certs/unsigned.jks", DFLT_PSWRD);
        KeyStore login1Sigma = loadKeyStore("certs/login1-sigma.jks", DFLT_PSWRD);

        assertEquals(certsCount(login1Alpha), 1);
        assertEquals(certsCount(login1Delta), 1);
        assertEquals(certsCount(login1AlphaExpired), 1);
        assertEquals(certsCount(unsigned), 1);
        assertEquals(certsCount(login1Sigma), 1);

        assertEquals(((X509Certificate)login1Alpha.getCertificate("login1Alpha")).getIssuerDN(),
            intermediateCaAlpha.getSubjectDN());

        assertEquals(((X509Certificate)login1AlphaExpired.getCertificate("login1AlphaExpired")).getIssuerDN(),
            intermediateCaAlpha.getSubjectDN());

        assertEquals(((X509Certificate)login1Delta.getCertificate("login1Delta")).getIssuerDN(),
            intermediateCaDelta.getSubjectDN());

        try {
            ((X509Certificate)login1AlphaExpired.getCertificate("login1AlphaExpired")).checkValidity();

            fail();
        } catch (Exception e) {
            assertTrue(hasCause(e, CertificateExpiredException.class));
        }

        X509Certificate cert;
        assertEquals((cert = (X509Certificate)unsigned.getCertificate("noSign")).getIssuerDN(),
            cert.getSubjectDN());
    }
}
