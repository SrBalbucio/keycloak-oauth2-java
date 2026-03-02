package balbucio.keycloakoauth;

import lombok.Getter;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Starts the OAuth2 Authorization Code + PKCE flow: generates state and PKCE,
 * stores code_verifier by state, builds the Keycloak authorization URL, and opens the browser.
 */
@Getter
public class KeycloakAuthProvider {

    private static final int STATE_BYTES = 32;

    private final KeycloakAuthConfig config;
    /**
     * -- GETTER --
     *  Returns the storage map (state -> code_verifier) for use by the callback handler.
     */
    private final ConcurrentHashMap<String, String> stateToCodeVerifier = new ConcurrentHashMap<String, String>();

    public KeycloakAuthProvider(KeycloakAuthConfig config) {
        this.config = config;
    }

    /**
     * Generates state and PKCE, stores code_verifier, builds the authorization URL and opens the default browser.
     * The redirect will hit the callback server; the callback must use the same provider to retrieve the code_verifier.
     * @return Authorization URL
     */
    public String startLogin() {
        String state = generateState();
        String codeVerifier = PkceUtil.generateCodeVerifier();
        String codeChallenge = PkceUtil.generateCodeChallenge(codeVerifier);
        stateToCodeVerifier.put(state, codeVerifier);

        String authUrl = buildAuthorizationUrl(state, codeChallenge);
        openBrowser(authUrl);
        return authUrl;
    }

    /**
     * Retrieves and removes the code_verifier for the given state. Returns null if state is unknown or already used.
     */
    public String consumeCodeVerifierForState(String state) {
        return stateToCodeVerifier.remove(state);
    }

    private String generateState() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[STATE_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String buildAuthorizationUrl(String state, String codeChallenge) {
        StringBuilder sb = new StringBuilder(config.getAuthorizationEndpoint());
        sb.append("?response_type=code");
        sb.append("&client_id=").append(urlEncode(config.getClientId()));
        sb.append("&redirect_uri=").append(urlEncode(config.getRedirectUri()));
        sb.append("&scope=").append(urlEncode(config.getScope()));
        sb.append("&state=").append(urlEncode(state));
        sb.append("&code_challenge=").append(urlEncode(codeChallenge));
        sb.append("&code_challenge_method=S256");
        return sb.toString();
    }

    private static String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 not supported", e);
        }
    }

    private void openBrowser(String url) {
        try {
            URI uri = new URI(url);
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(uri);
            } else {
                System.err.println("Open this URL in your browser: " + url);
            }
        } catch (URISyntaxException | IOException e) {
            System.err.println("Could not open browser. Open this URL manually: " + url);
        }
    }
}
