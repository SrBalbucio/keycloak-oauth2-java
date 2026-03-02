package balbucio.keycloakoauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Starts the OAuth2 Authorization Code + PKCE flow: generates state and PKCE,
 * stores code_verifier by state, builds the Keycloak authorization URL, and opens the browser.
 */
@Getter
public class KeycloakAuthProvider {

    private static final int STATE_BYTES = 32;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final OkHttpClient HTTP_CLIENT = new OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build();

    private final KeycloakAuthConfig config;
    /**
     * -- GETTER --
     *  Returns the storage map (state -> code_verifier) for use by the callback handler.
     */
    private final ConcurrentHashMap<String, String> stateToCodeVerifier = new ConcurrentHashMap<>();

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

    /**
     * Refreshes the access token using the refresh token from the given TokenData.
     * Calls the Keycloak token endpoint with grant_type=refresh_token (public client: client_id only).
     *
     * @param tokenData the current tokens, must contain a non-null refresh token
     * @return new TokenData with the refreshed access token (and possibly a new refresh token)
     * @throws IllegalArgumentException if tokenData or its refresh token is null
     * @throws IOException if the token request fails (e.g. refresh token expired, network error)
     */
    public TokenData refreshTokens(TokenData tokenData) throws IOException {
        if (tokenData == null) {
            throw new IllegalArgumentException("TokenData must not be null");
        }
        String refreshToken = tokenData.getRefreshToken();
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("TokenData must contain a refresh token");
        }
        String tokenResponseBody = exchangeRefreshToken(refreshToken);
        JsonNode json = OBJECT_MAPPER.readTree(tokenResponseBody);
        TokenData refreshed = TokenData.fromJson(json);
        if (refreshed == null) {
            throw new IOException("Token endpoint did not return a valid token response");
        }
        return refreshed;
    }

    private String exchangeRefreshToken(String refreshToken) throws IOException {
        FormBody form = new FormBody.Builder()
                .add("grant_type", "refresh_token")
                .add("client_id", config.getClientId())
                .add("refresh_token", refreshToken)
                .build();

        Request request = new Request.Builder()
                .url(config.getTokenEndpoint())
                .post(form)
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();

        Response response = HTTP_CLIENT.newCall(request).execute();
        okhttp3.ResponseBody responseBody = response.body();
        if (!response.isSuccessful()) {
            String body = responseBody != null ? responseBody.string() : "";
            throw new IOException("Refresh token request failed: " + response.code() + " " + body);
        }
        if (responseBody == null) {
            throw new IOException("Empty token response");
        }
        String body = responseBody.string();
        return body;
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
