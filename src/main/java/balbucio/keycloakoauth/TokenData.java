package balbucio.keycloakoauth;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Value;
import org.jetbrains.annotations.Nullable;

/**
 * Parsed token response from the OAuth2/OpenID Connect token endpoint.
 * Contains the main fields returned by Keycloak (and standard OAuth2).
 */
@Value
public class TokenData {

    /** Access token (JWT) to use for API calls. */
    String accessToken;

    /** Refresh token; may be null if not returned. */
    @Nullable
    String refreshToken;

    /** ID token (JWT); typically present when scope includes openid. */
    @Nullable
    String idToken;

    /** Lifetime of the access token in seconds. */
    @Nullable
    Integer expiresIn;

    /** Lifetime of the refresh token in seconds (Keycloak). */
    @Nullable
    Integer refreshExpiresIn;

    /** Token type, usually "Bearer". */
    @Nullable
    String tokenType;

    /** Granted scope(s). */
    @Nullable
    String scope;

    /** Parsed ID token claims (sub, iss, aud, exp, preferred_username, etc.). Null if no id_token or parse failed. */
    @Nullable
    IdTokenData idTokenData;

    /**
     * Parses a token response from the given JsonNode.
     *
     * @param node the JSON from the token endpoint; may be null
     * @return TokenData instance, or null if node is null or missing access_token
     */
    @Nullable
    public static TokenData fromJson(@Nullable JsonNode node) {
        if (node == null || node.isNull() || !node.has("access_token")) {
            return null;
        }
        String idTokenRaw = textOrNull(node, "id_token");
        return new TokenData(
                node.get("access_token").asText(),
                textOrNull(node, "refresh_token"),
                idTokenRaw,
                intOrNull(node, "expires_in"),
                intOrNull(node, "refresh_expires_in"),
                textOrNull(node, "token_type"),
                textOrNull(node, "scope"),
                IdTokenData.fromJwt(idTokenRaw)
        );
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode n = node.get(field);
        return (n == null || n.isNull() || n.isMissingNode()) ? null : n.asText();
    }

    private static Integer intOrNull(JsonNode node, String field) {
        JsonNode n = node.get(field);
        if (n == null || n.isNull() || n.isMissingNode()) {
            return null;
        }
        return n.isNumber() ? n.intValue() : null;
    }
}
