package dev.p2pobservatory.chat;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    private android.net.ConnectivityManager connectivity;
    private android.net.ConnectivityManager.NetworkCallback networkCallback;
    private void lifecycle(String type) {
        if (getBridge() != null) runOnUiThread(() -> {
            if (getBridge() != null) getBridge().getWebView().evaluateJavascript(
                "window.p2pMobileLifecycle && window.p2pMobileLifecycle('" + type + "')", null);
        });
    }
    @Override public void onPause() {
        // Deliver before WebView timers can be suspended; JS stops every tracked audio track.
        lifecycle("pause");
        super.onPause();
    }
    @Override public void onResume() { super.onResume(); lifecycle("resume"); }
    @Override public void onDestroy() {
        lifecycle("pause");
        if (connectivity != null && networkCallback != null) connectivity.unregisterNetworkCallback(networkCallback);
        super.onDestroy();
    }
    @Override public void onCreate(Bundle state) {
        registerPlugin(SaveFilePlugin.class);
        super.onCreate(state);
        connectivity = (android.net.ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        networkCallback = new android.net.ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(android.net.Network network) { lifecycle("network-change"); }
            @Override public void onLost(android.net.Network network) { lifecycle("network-change"); }
        };
        if (connectivity != null) connectivity.registerDefaultNetworkCallback(networkCallback);
        getBridge().getWebView().setWebViewClient(new com.getcapacitor.BridgeWebViewClient(getBridge()) {
            @Override public boolean shouldOverrideUrlLoading(android.webkit.WebView view, android.webkit.WebResourceRequest request) {
                // App never navigates away; signaling uses WSS, not WebView navigation.
                return true;
            }
        });
        getBridge().getWebView().setWebChromeClient(new com.getcapacitor.BridgeWebChromeClient(getBridge()) {
            @Override public void onPermissionRequest(android.webkit.PermissionRequest request) {
                if (!"https://localhost".equals(request.getOrigin().toString()) || request.getResources().length != 1 ||
                    !android.webkit.PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(request.getResources()[0])) {
                    request.deny(); return;
                }
                super.onPermissionRequest(request);
            }
        });
    }
}
