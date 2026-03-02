package balbucio.keycloakoauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

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
     * Exchanges code for tokens and returns HTML with the result.
     */
    public String handleCallback(String code, String state, String error, String errorDescription) {
        KeycloakAuthConfig config = provider.getConfig();

        if (error != null) {
            return buildErrorPage(error, errorDescription != null ? errorDescription : "");
        }

        if (code == null || code.isEmpty() || state == null || state.isEmpty()) {
            return buildErrorPage("invalid_request", "Missing code or state parameter.");
        }

        String codeVerifier = provider.consumeCodeVerifierForState(state);
        if (codeVerifier == null) {
            return buildErrorPage("invalid_state", "Unknown or already used state. Please start the login again.");
        }

        try {
            String tokenResponseBody = exchangeCodeForTokens(config, code, codeVerifier);
            JsonNode json = OBJECT_MAPPER.readTree(tokenResponseBody);
            return buildSuccessPage(json);
        } catch (IOException e) {
            return buildErrorPage("token_exchange_failed", e.getMessage());
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
        if (!response.isSuccessful()) {
            String body = response.body() != null ? response.body().string() : "";
            throw new IOException("Token request failed: " + response.code() + " " + body);
        }
        if (response.body() == null) {
            throw new IOException("Empty token response");
        }
        return response.body().string();
    }

    private static String buildSuccessPage(JsonNode json) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Login successful</title></head><body>");
        html.append("<h1>Login successful</h1>");
        html.append("<p>Tokens received. You can close this page.</p>");
        html.append("<pre style=\"background:#f5f5f5;padding:1em;overflow:auto;\">");
        html.append(escapeHtml(json.toString()));
        html.append("</pre>");
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
