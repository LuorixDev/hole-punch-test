package dev.p2pobservatory.chat;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override public void onCreate(Bundle state) {
        registerPlugin(SaveFilePlugin.class);
        super.onCreate(state);
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
