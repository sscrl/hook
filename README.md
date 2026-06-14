# FlyBypass LSPatch Module

LSPatch/Xposed module for bypassing VPN/Proxy/SSL detection.

## Target Package

`com.wer.bdf`

## Entry Point

`com.fly.bypass.HookEntry`

## Features

- Bypass `NetworkCapabilities.hasTransport(VPN)`
- Bypass `NetworkInfo` VPN detection
- Bypass `NetworkInterface` tun/tap/ppp/wg/ipsec naming
- Bypass `ConnectivityManager.getAllNetworks` VPN filter
- Hide proxy settings: `System.getProperty` / `System.getenv` / `ProxySelector`
- SSL pinning bypass: `SSLContext.init` + Conscrypt `TrustManagerImpl`
- OkHttp `CertificatePinner.check` bypass
- Redirect `/proc/net/route`, `/proc/net/dev`, `/proc/net/if_inet6` to `/dev/null`
- Log tag: `FlyBypass`

## Build

```bash
gradle assembleDebug
```

Or use GitHub Actions.

## Usage

1. Build APK
2. Open LSPatch
3. Patch target APK with this module
4. Install patched APK