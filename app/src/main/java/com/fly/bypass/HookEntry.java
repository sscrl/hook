package com.fly.bypass;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.lang.reflect.Method;
import java.net.NetworkInterface;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookEntry implements IXposedHookLoadPackage {
    private static final String TAG = "FlyBypass";
    private static final String TARGET = "com.wer.bdf";

    private static void log(String s) {
        XposedBridge.log(TAG + ": " + s);
        Log.i(TAG, s);
    }

    private static boolean isVpnName(String s) {
        if (s == null) return false;
        String x = s.toLowerCase();
        return x.startsWith("tun") || x.startsWith("tap") || x.startsWith("ppp") ||
                x.startsWith("wg") || x.contains("ipsec") || x.contains("vpn") || x.contains("utun");
    }

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!TARGET.equals(lpparam.packageName)) return;
        log("loaded in " + lpparam.packageName + ", process=" + lpparam.processName);

        hookVpnJava();
        hookProxyJava();
        hookSslJava(lpparam.classLoader);
        hookProcFileJava();
        hookHttpLogs(lpparam.classLoader);
    }

    private void hookVpnJava() {
        try {
            XposedHelpers.findAndHookMethod(NetworkCapabilities.class, "hasTransport", int.class, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    int t = (Integer) param.args[0];
                    if (t == 4) {
                        log("NetworkCapabilities.hasTransport(VPN) => false");
                        param.setResult(false);
                    }
                }
            });
        } catch (Throwable t) { log("hook hasTransport fail " + t); }

        try {
            XposedHelpers.findAndHookMethod(NetworkCapabilities.class, "toString", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    String s = (String) param.getResult();
                    if (s != null && s.toLowerCase().contains("vpn")) {
                        param.setResult(s.replace("VPN", "WIFI").replace("vpn", "wifi"));
                    }
                }
            });
        } catch (Throwable t) { log("hook cap toString fail " + t); }

        try {
            XposedHelpers.findAndHookMethod(NetworkInfo.class, "getType", XC_MethodReplacement.returnConstant(1));
            XposedHelpers.findAndHookMethod(NetworkInfo.class, "getTypeName", XC_MethodReplacement.returnConstant("WIFI"));
            XposedHelpers.findAndHookMethod(NetworkInfo.class, "getSubtypeName", XC_MethodReplacement.returnConstant(""));
        } catch (Throwable t) { log("hook NetworkInfo fail " + t); }

        try {
            XposedHelpers.findAndHookMethod(ConnectivityManager.class, "getAllNetworks", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    Network[] arr = (Network[]) param.getResult();
                    if (arr == null) return;
                    List<Network> keep = new ArrayList<>();
                    ConnectivityManager cm = (ConnectivityManager) param.thisObject;
                    for (Network n : arr) {
                        try {
                            NetworkCapabilities c = cm.getNetworkCapabilities(n);
                            if (c != null && c.hasTransport(4)) continue;
                        } catch (Throwable ignored) {}
                        keep.add(n);
                    }
                    param.setResult(keep.toArray(new Network[0]));
                }
            });
        } catch (Throwable t) { log("hook getAllNetworks fail " + t); }

        try {
            XposedHelpers.findAndHookMethod(NetworkInterface.class, "getName", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    String n = (String) param.getResult();
                    if (isVpnName(n)) { param.setResult("wlan0"); }
                }
            });
            XposedHelpers.findAndHookMethod(NetworkInterface.class, "getDisplayName", new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    String n = (String) param.getResult();
                    if (isVpnName(n)) { param.setResult("wlan0"); }
                }
            });
            XposedHelpers.findAndHookMethod(NetworkInterface.class, "isUp", XC_MethodReplacement.returnConstant(true));
        } catch (Throwable t) { log("hook NetworkInterface fail " + t); }
    }

    private void hookProxyJava() {
        try {
            XposedHelpers.findAndHookMethod(System.class, "getProperty", String.class, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    String k = (String) param.args[0];
                    if (k != null && (k.toLowerCase().contains("proxy") || k.equals("http.proxyHost") || k.equals("https.proxyHost"))) {
                        param.setResult(null);
                    }
                }
            });
        } catch (Throwable t) { log("hook System.getProperty fail " + t); }

        try {
            XposedHelpers.findAndHookMethod(System.class, "getenv", String.class, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    String k = (String) param.args[0];
                    if (k != null && k.toUpperCase().contains("PROXY")) { param.setResult(null); }
                }
            });
        } catch (Throwable t) { log("hook System.getenv fail " + t); }

        try {
            XposedHelpers.findAndHookMethod(ProxySelector.class, "getDefault", XC_MethodReplacement.returnConstant(null));
            XposedHelpers.findAndHookMethod(Proxy.class, "type", XC_MethodReplacement.returnConstant(Proxy.Type.DIRECT));
        } catch (Throwable t) { log("hook Proxy fail " + t); }
    }

    private void hookSslJava(ClassLoader cl) {
        try {
            final X509TrustManager trustAll = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            };
            XposedHelpers.findAndHookMethod(SSLContext.class, "init",
                    javax.net.ssl.KeyManager[].class, TrustManager[].class, SecureRandom.class,
                    new XC_MethodHook() {
                        @Override protected void beforeHookedMethod(MethodHookParam param) {
                            param.args[1] = new TrustManager[]{ trustAll };
                        }
                    });
        } catch (Throwable t) { log("hook SSLContext fail " + t); }

        try {
            Class<?> cls = XposedHelpers.findClass("com.android.org.conscrypt.TrustManagerImpl", null);
            XposedBridge.hookAllMethods(cls, "checkTrustedRecursive", new XC_MethodReplacement() {
                @Override protected Object replaceHookedMethod(MethodHookParam param) {
                    return new ArrayList<X509Certificate>();
                }
            });
            XposedBridge.hookAllMethods(cls, "verifyChain", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(param.args[0]);
                }
            });
        } catch (Throwable t) { log("hook TrustManagerImpl fail " + t); }

        try {
            XposedHelpers.findAndHookMethod(javax.net.ssl.HttpsURLConnection.class,
                    "setHostnameVerifier", HostnameVerifier.class, XC_MethodReplacement.DO_NOTHING);
            XposedHelpers.findAndHookMethod(javax.net.ssl.HttpsURLConnection.class,
                    "setDefaultHostnameVerifier", HostnameVerifier.class, XC_MethodReplacement.DO_NOTHING);
        } catch (Throwable t) { log("hook HttpsURLConnection fail " + t); }

        try {
            Class<?> pinner = XposedHelpers.findClassIfExists("okhttp3.CertificatePinner", cl);
            if (pinner != null) {
                XposedBridge.hookAllMethods(pinner, "check", XC_MethodReplacement.DO_NOTHING);
            }
        } catch (Throwable t) { log("hook OkHttp pinner fail " + t); }
    }

    private void hookProcFileJava() {
        try {
            XposedHelpers.findAndHookConstructor(File.class, String.class, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) {
                    String p = (String) param.args[0];
                    if (p != null && (p.contains("/proc/net/route") || p.contains("/proc/net/dev")
                            || p.contains("/proc/net/if_inet6"))) {
                        param.args[0] = "/dev/null";
                    }
                }
            });
        } catch (Throwable t) { log("hook File ctor fail " + t); }
    }

    private void hookHttpLogs(ClassLoader cl) {
        try {
            Class<?> urlCls = XposedHelpers.findClassIfExists("okhttp3.Request$Builder", cl);
            if (urlCls != null) {
                XposedHelpers.findAndHookMethod(urlCls, "url", String.class, new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) {
                        log("OkHttp url: " + param.args[0]);
                    }
                });
            }
        } catch (Throwable t) { log("hook okhttp log fail " + t); }

        try {
            XposedHelpers.findAndHookMethod(android.webkit.WebView.class, "loadUrl", String.class,
                    new XC_MethodHook() {
                        @Override protected void beforeHookedMethod(MethodHookParam param) {
                            log("WebView.loadUrl " + param.args[0]);
                        }
                    });
        } catch (Throwable t) { log("hook webview log fail " + t); }
    }
}