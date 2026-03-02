package balbucio.keycloakoauth;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.Value;

/**
 * Result of handling the OAuth2 callback: contains the HTML page to return to the client
 * and, on success, the tokens from the token exchange (raw and parsed).
 */
@Value
public class CallbackResult {

    /** Whether the callback was successful (tokens were obtained). */
    boolean success;

    /** Tokens returned by the token endpoint (access_token, refresh_token, id_token, etc.). Null on error. */
    JsonNode tokens;

    /** Parsed token fields (accessToken, refreshToken, idToken, expiresIn, etc.). Null on error. */
    TokenData tokenData;

    /** HTML page to send in the response (success or error page). */
    String html;

    /** OAuth2 error code when success is false. Null on success. */
    String error;

    /** OAuth2 error description when success is false. Null on success. */
    String errorDescription;

    public static CallbackResult success(JsonNode tokens, String html) {
        return new CallbackResult(true, tokens, TokenData.fromJson(tokens), html, null, null);
    }

    public static CallbackResult error(String error, String errorDescription, String html) {
        return new CallbackResult(false, null, null, html, error, errorDescription);
    }
}
