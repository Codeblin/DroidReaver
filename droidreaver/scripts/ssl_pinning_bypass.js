/**
 * Universal Android SSL pinning bypass (Frida fallback).
 * Hooks common TrustManager, OkHttp, and Conscrypt paths.
 */
Java.perform(function () {
    console.log("[droidreaver] SSL pinning bypass active");

    function trustAllManagers() {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManager = Java.registerClass({
            name: "com.droidreaver.ssl.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () {
                    return [];
                },
            },
        });
        return [TrustManager.$new()];
    }

    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var init = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        );
        var managers = trustAllManagers();
        init.implementation = function (km, tm, sr) {
            init.call(this, km, managers, sr);
        };
    } catch (e) {
        console.log("[droidreaver] SSLContext.init hook skipped: " + e);
    }

    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (
            untrustedChain,
            trustAnchorChain,
            host,
            clientAuth,
            ocspData,
            tlsSctData
        ) {
            console.log("[droidreaver] TrustManagerImpl bypass: " + host);
            return untrustedChain;
        };
    } catch (e) {}

    try {
        var OkHttpPinner = Java.use("okhttp3.CertificatePinner");
        OkHttpPinner.check.overload("java.lang.String", "java.util.List").implementation = function (
            hostname,
            peerCertificates
        ) {
            console.log("[droidreaver] OkHttp3 pinner bypass: " + hostname);
        };
    } catch (e) {}

    try {
        var OkHttpPinner2 = Java.use("okhttp3.CertificatePinner");
        OkHttpPinner2.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation =
            function (hostname, certs) {
                console.log("[droidreaver] OkHttp3 pinner bypass (certs): " + hostname);
            };
    } catch (e) {}

    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            return null;
        };
        HttpsURLConnection.setSSLSocketFactory.implementation = function (factory) {
            return null;
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
            return null;
        };
    } catch (e) {}
});
