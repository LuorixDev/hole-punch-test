package dev.p2pobservatory.chat;

/**
 * The Capacitor WebView origin for this app.
 *
 * <p>The scheme follows {@code server.androidScheme} in p2pchat/capacitor.config.json: the page is
 * served from {@code http://localhost} (scheme "http") or {@code https://localhost} (scheme
 * "https"). Both are accepted here so a TLS build stays buildable, but only these two exact
 * loopback origins are ever trusted; anything else is denied.
 *
 * <p>Why the page is not a remote origin: Capacitor serves the packaged assets from an internal
 * loopback server, so the WebView never navigates to a network origin.
 */
final class LocalOrigin {
    static final String HTTP = "http://localhost";
    static final String HTTPS = "https://localhost";

    /** True when {@code origin} is exactly one of the two loopback page origins. */
    static boolean isPageOrigin(String origin) {
        return HTTP.equals(origin) || HTTPS.equals(origin);
    }

    /** True when {@code url} is the packaged page itself (origin plus path), or the bare origin. */
    static boolean isLocalPageUrl(String url) {
        if (url == null) return false;
        return url.equals(HTTP) || url.startsWith(HTTP + "/") || url.equals(HTTPS) || url.startsWith(HTTPS + "/");
    }

    private LocalOrigin() {}
}
