/**
 * Android SSL pinning bypass for authorized lab / MAPT use.
 *
 * Java + common third-party stacks, then best-effort libssl verify callbacks.
 * Each hook is isolated: a missing class must not kill the Frida session.
 * Spawn the app so these run before TLS is initialized.
 */
var TAG = "[droidreaver] ";
var hooked = [];
var nativeKeepAlive = [];

function log(msg) {
    console.log(TAG + msg);
}

function tryHook(name, fn) {
    try {
        fn();
        hooked.push(name);
        log("hooked " + name);
    } catch (e) {
        /* class or overload not in this process */
    }
}

function uniqueClassName(base) {
    return base + "." + Date.now() + "." + Math.floor(Math.random() * 1e6);
}

function findExport(modName, expName) {
    try {
        if (typeof Module.findExportByName === "function") {
            return Module.findExportByName(modName, expName);
        }
    } catch (e) {}
    try {
        var mod =
            typeof Process.findModuleByName === "function"
                ? Process.findModuleByName(modName)
                : Process.getModuleByName(modName);
        if (!mod) {
            return null;
        }
        if (typeof mod.findExportByName === "function") {
            return mod.findExportByName(expName);
        }
        return mod.getExportByName(expName);
    } catch (e) {
        return null;
    }
}

function hookNativeTls() {
    var customOk = new NativeCallback(
        function (_ssl, _outAlert) {
            return 0;
        },
        "int",
        ["pointer", "pointer"]
    );
    var opensslOk = new NativeCallback(
        function (_preverifyOk, _ctx) {
            return 1;
        },
        "int",
        ["int", "pointer"]
    );
    nativeKeepAlive.push(customOk, opensslOk);

    var names = [
        "SSL_CTX_set_custom_verify",
        "SSL_set_custom_verify",
        "SSL_CTX_set_verify",
        "SSL_set_verify",
    ];
    var modules = ["libssl.so", "libboringssl.so", "libconscrypt_jni.so"];
    names.forEach(function (exp) {
        modules.forEach(function (mod) {
            try {
                var addr = findExport(mod, exp);
                if (!addr) {
                    return;
                }
                var cb = exp.indexOf("custom_verify") !== -1 ? customOk : opensslOk;
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        args[2] = cb;
                    },
                });
                hooked.push(mod + "!" + exp);
                log("hooked " + mod + "!" + exp);
            } catch (e) {
                log("native " + exp + " skipped: " + e);
            }
        });
    });
}

function hookJava() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");

    var TrustAll = Java.registerClass({
        name: uniqueClassName("com.droidreaver.ssl.TrustAll"),
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function () {},
            checkServerTrusted: function () {},
            getAcceptedIssuers: function () {
                return [];
            },
        },
    });
    var AllowAllHosts = Java.registerClass({
        name: uniqueClassName("com.droidreaver.ssl.AllowAllHosts"),
        implements: [HostnameVerifier],
        methods: {
            verify: function (_hostname, _session) {
                return true;
            },
        },
    });
    var trustAll = [TrustAll.$new()];
    var allowHosts = AllowAllHosts.$new();

    tryHook("javax.net.ssl.SSLContext.init", function () {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var init = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        );
        init.implementation = function (km, _tm, sr) {
            init.call(this, km, trustAll, sr);
        };
    });

    tryHook("javax.net.ssl.HttpsURLConnection", function () {
        var Conn = Java.use("javax.net.ssl.HttpsURLConnection");
        var setDefault = Conn.setDefaultHostnameVerifier.overload(
            "javax.net.ssl.HostnameVerifier"
        );
        setDefault.implementation = function (_v) {
            setDefault.call(Conn, allowHosts);
        };
        var setInst = Conn.setHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
        setInst.implementation = function (_v) {
            setInst.call(this, allowHosts);
        };
        Conn.getHostnameVerifier.implementation = function () {
            return allowHosts;
        };
    });

    tryHook("javax.net.ssl.X509TrustManager", function () {
        ["checkServerTrusted", "checkClientTrusted"].forEach(function (method) {
            X509TrustManager[method].overloads.forEach(function (ovl) {
                ovl.implementation = function () {};
            });
        });
    });

    var conscryptTrust = [
        "com.android.org.conscrypt.TrustManagerImpl",
        "org.conscrypt.TrustManagerImpl",
        "com.google.org.conscrypt.TrustManagerImpl",
    ];
    conscryptTrust.forEach(function (clsName) {
        tryHook(clsName + ".verifyChain", function () {
            var TMI = Java.use(clsName);
            TMI.verifyChain.implementation = function (untrustedChain) {
                return untrustedChain;
            };
        });
        tryHook(clsName + ".checkTrustedRecursive", function () {
            var TMI = Java.use(clsName);
            TMI.checkTrustedRecursive.implementation = function (
                certs,
                _ocsp,
                _tlsSct,
                _host,
                _clientAuth,
                _untrustedChain,
                _trustAnchorChain,
                _used
            ) {
                return certs;
            };
        });
        tryHook(clsName + ".checkTrusted", function () {
            var TMI = Java.use(clsName);
            TMI.checkTrusted.overloads.forEach(function (ovl) {
                ovl.implementation = function () {
                    var ArrayList = Java.use("java.util.ArrayList");
                    return ArrayList.$new();
                };
            });
        });
    });

    tryHook("com.android.org.conscrypt.Platform.checkServerTrusted", function () {
        var Platform = Java.use("com.android.org.conscrypt.Platform");
        Platform.checkServerTrusted.overloads.forEach(function (ovl) {
            ovl.implementation = function () {};
        });
    });

    tryHook("android.security.net.config.NetworkSecurityTrustManager", function () {
        var NSTM = Java.use("android.security.net.config.NetworkSecurityTrustManager");
        if (NSTM.checkPins) {
            NSTM.checkPins.implementation = function () {};
        }
        NSTM.checkServerTrusted.overloads.forEach(function (ovl) {
            ovl.implementation = function () {};
        });
    });

    tryHook("android.security.net.config.RootTrustManager", function () {
        var RTM = Java.use("android.security.net.config.RootTrustManager");
        RTM.checkServerTrusted.overloads.forEach(function (ovl) {
            ovl.implementation = function () {};
        });
    });

    function hookOkHttpPinner(clsName) {
        tryHook(clsName, function () {
            var Pinner = Java.use(clsName);
            Pinner.check.overloads.forEach(function (ovl) {
                ovl.implementation = function () {};
            });
            if (Pinner["check$okhttp"]) {
                Pinner["check$okhttp"].overloads.forEach(function (ovl) {
                    ovl.implementation = function () {};
                });
            }
            if (Pinner.findMatchingPins) {
                Pinner.findMatchingPins.implementation = function () {
                    return Java.use("java.util.ArrayList").$new();
                };
            }
        });
    }
    hookOkHttpPinner("okhttp3.CertificatePinner");
    hookOkHttpPinner("com.squareup.okhttp.CertificatePinner");
    hookOkHttpPinner("okhttp3.internal.tls.CertificatePinner");

    [
        "okhttp3.internal.tls.OkHostnameVerifier",
        "okhttp3.internal.hostname.OkHostnameVerifier",
        "com.squareup.okhttp.internal.tls.OkHostnameVerifier",
    ].forEach(function (clsName) {
        tryHook(clsName, function () {
            var V = Java.use(clsName);
            V.verify.overloads.forEach(function (ovl) {
                ovl.implementation = function () {
                    return true;
                };
            });
        });
    });

    [
        "com.datatheorem.android.trustkit.pinning.OkHttp3Helper",
        "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
        "com.datatheorem.android.trustkit.pinning.TrustKitPinningTrustManager",
    ].forEach(function (clsName) {
        tryHook(clsName, function () {
            var C = Java.use(clsName);
            C.class.getDeclaredMethods().forEach(function (m) {
                var n = m.getName();
                if (n.indexOf("check") === -1 && n.indexOf("verify") === -1) {
                    return;
                }
                try {
                    C[n].overloads.forEach(function (ovl) {
                        ovl.implementation = function () {
                            var ret = ovl.returnType.className;
                            if (ret === "boolean") {
                                return true;
                            }
                        };
                    });
                } catch (e) {}
            });
        });
    });

    tryHook("org.apache.http.conn.ssl.SSLSocketFactory", function () {
        var F = Java.use("org.apache.http.conn.ssl.SSLSocketFactory");
        F.isSecure.implementation = function () {
            return true;
        };
    });
    tryHook("org.apache.http.conn.ssl.AbstractVerifier", function () {
        var V = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        V.verify.overloads.forEach(function (ovl) {
            ovl.implementation = function () {};
        });
    });

    tryHook("android.webkit.WebViewClient.onReceivedSslError", function () {
        var WVC = Java.use("android.webkit.WebViewClient");
        WVC.onReceivedSslError.implementation = function (_view, handler, _error) {
            handler.proceed();
        };
    });

    tryHook("org.chromium.net.X509Util", function () {
        var U = Java.use("org.chromium.net.X509Util");
        if (U.verifyServerCertificates) {
            U.verifyServerCertificates.overloads.forEach(function (ovl) {
                ovl.implementation = function () {};
            });
        }
    });

    log("Java SSL hooks installed (" + hooked.length + ")");
}

hookNativeTls();

if (Java.available) {
    Java.perform(hookJava);
} else {
    log("no Java VM — native TLS hooks only");
}

log("SSL pinning bypass ready (" + hooked.length + " hooks)");
