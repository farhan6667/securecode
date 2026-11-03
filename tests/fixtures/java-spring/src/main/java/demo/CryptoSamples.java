package demo;

// Test fixture for semgrep/java-spring.yml. Never compiled or run.

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CryptoSamples {

    static class TrustEverything implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        // expect: java-trust-all-certificates
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class PinnedTrust implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            Pins.verify(chain);
        }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    void hostnames(HttpsURLConnection conn) {
        // expect: java-trust-all-hostnames-lambda
        conn.setHostnameVerifier((host, session) -> true);
        // expect: java-trust-all-hostnames
        Object v = NoopHostnameVerifier.INSTANCE;
        // expect: java-trust-all-hostnames
        HostnameVerifier any = new HostnameVerifier() { public boolean verify(String h, SSLSession s) { return true; } };
    }

    String hashPassword(String password) throws Exception {
        // expect: java-weak-password-hash
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(password.getBytes()));
    }

    String encodePassword(String password) {
        return new BCryptPasswordEncoder().encode(password);
    }

    String fileChecksum(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return new String(md.digest(data));
    }

    String resetToken() {
        // expect: java-insecure-random-token
        Random r = new Random();
        return Long.toHexString(r.nextLong());
    }

    String otp() {
        // expect: java-insecure-random-token
        int v = (int) (Math.random() * 900000) + 100000;
        return String.valueOf(v);
    }

    String secureToken() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return java.util.Base64.getUrlEncoder().encodeToString(b);
    }

    void shuffleCards(List<String> cards) {
        Collections.shuffle(cards, new Random());
    }
}
