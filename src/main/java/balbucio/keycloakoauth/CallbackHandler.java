package balbucio.keycloakoauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Handles the OAuth2 callback: validates state, exchanges the authorization code for tokens
 * via the Keycloak token endpoint, and returns a success or error page.
 */
public class CallbackHandler {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final OkHttpClient HTTP_CLIENT = new OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build();

    private final KeycloakAuthProvider provider;

    public CallbackHandler(KeycloakAuthProvider provider) {
        this.provider = provider;
    }

    /**
     * Handles GET /callback. Query params: code, state (on success) or error, error_description (on error).
     * Exchanges code for tokens and returns a result containing the HTML page and, on success, the tokens.
     */
    public CallbackResult handleCallback(String code, String state, String error, String errorDescription) {
        KeycloakAuthConfig config = provider.getConfig();

        if (error != null) {
            String html = buildErrorPage(error, errorDescription != null ? errorDescription : "");
            return CallbackResult.error(error, errorDescription, html);
        }

        if (code == null || code.isEmpty() || state == null || state.isEmpty()) {
            String html = buildErrorPage("invalid_request", "Missing code or state parameter.");
            return CallbackResult.error("invalid_request", "Missing code or state parameter.", html);
        }

        String codeVerifier = provider.consumeCodeVerifierForState(state);
        if (codeVerifier == null) {
            String html = buildErrorPage("invalid_state", "Unknown or already used state. Please start the login again.");
            return CallbackResult.error("invalid_state", "Unknown or already used state. Please start the login again.", html);
        }

        try {
            String tokenResponseBody = exchangeCodeForTokens(config, code, codeVerifier);
            JsonNode json = OBJECT_MAPPER.readTree(tokenResponseBody);
            String html = buildSuccessPage(config.isDevMode() ? json : null);
            return CallbackResult.success(json, html);
        } catch (IOException e) {
            String html = buildErrorPage("token_exchange_failed", e.getMessage());
            return CallbackResult.error("token_exchange_failed", e.getMessage(), html);
        }
    }

    private String exchangeCodeForTokens(KeycloakAuthConfig config, String code, String codeVerifier) throws IOException {
        FormBody form = new FormBody.Builder()
                .add("grant_type", "authorization_code")
                .add("code", code)
                .add("redirect_uri", config.getRedirectUri())
                .add("client_id", config.getClientId())
                .add("code_verifier", codeVerifier)
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
            throw new IOException("Token request failed: " + response.code() + " " + body);
        }
        if (responseBody == null) {
            throw new IOException("Empty token response");
        }
        return responseBody.string();
    }

    private static String buildSuccessPage(@Nullable JsonNode json) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Login successful</title></head><body>");
        html.append("<h1>Login successful</h1>");
        html.append("<p>You can close this page.</p>");

        if (json != null) {
            html.append("<pre style=\"background:#f5f5f5;padding:1em;overflow:auto;\">");
            html.append(escapeHtml(json.toString()));
            html.append("</pre>");
        }

        html.append("</body></html>");
        return html.toString();
    }

    private static String buildErrorPage(String error, String description) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Login error</title></head><body>");
        html.append("<h1>Login error</h1>");
        html.append("<p><strong>").append(escapeHtml(error)).append("</strong></p>");
        if (description != null && !description.isEmpty()) {
            html.append("<p>").append(escapeHtml(description)).append("</p>");
        }
        html.append("</body></html>");
        return html.toString();
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
