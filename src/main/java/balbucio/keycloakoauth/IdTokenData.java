package balbucio.keycloakoauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Value;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Parsed claims from the OpenID Connect ID token (JWT payload).
 * Contains the standard registered claims and common profile claims.
 */
@Value
public class IdTokenData {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Subject – unique identifier for the user (required). */
    String sub;

    /** Issuer – who issued the token (required). */
    String iss;

    /** Audience – intended recipient(s), often the client_id (required). */
    String aud;

    /** Expiration time – Unix timestamp in seconds (required in OIDC). */
    @Nullable
    Long exp;

    /** Issued at – Unix timestamp in seconds (optional). */
    @Nullable
    Long iat;

    /** Authentication time – when the user authenticated (optional). */
    @Nullable
    Long authTime;

    /** Nonce – if sent in the authorization request (optional). */
    @Nullable
    String nonce;

    /** Preferred username (optional, common in Keycloak). */
    @Nullable
    String preferredUsername;

    /** Full name (optional). */
    @Nullable
    String name;

    /** Email address (optional). */
    @Nullable
    String email;

    /** Given name (optional). */
    @Nullable
    String givenName;

    /** Family name (optional). */
    @Nullable
    String familyName;

    /**
     * Parses the ID token JWT and extracts the payload claims.
     * Only decodes the payload; does not verify the signature.
     *
     * @param idToken the raw ID token JWT string; may be null or invalid
     * @return IdTokenData with known claims, or null if token is null/invalid
     */
    @Nullable
    public static IdTokenData fromJwt(@Nullable String idToken) {
        if (idToken == null || idToken.isEmpty()) {
            return null;
        }
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            return null;
        }
        try {
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            JsonNode node = MAPPER.readTree(payloadJson);
            if (!node.has("sub") || !node.has("iss") || !node.has("exp")) {
                return null;
            }
            return new IdTokenData(
                    node.get("sub").asText(),
                    node.get("iss").asText(),
                    audAsString(node),
                    longOrNull(node, "exp"),
                    longOrNull(node, "iat"),
                    longOrNull(node, "auth_time"),
                    textOrNull(node, "nonce"),
                    textOrNull(node, "preferred_username"),
                    textOrNull(node, "name"),
                    textOrNull(node, "email"),
                    textOrNull(node, "given_name"),
                    textOrNull(node, "family_name")
            );
        } catch (IllegalArgumentException | java.io.IOException e) {
            return null;
        }
    }

    private static String audAsString(JsonNode node) {
        JsonNode aud = node.get("aud");
        if (aud == null || aud.isNull() || aud.isMissingNode()) {
            return "";
        }
        if (aud.isArray() && aud.size() > 0) {
            return aud.get(0).asText();
        }
        return aud.asText();
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode n = node.get(field);
        return (n == null || n.isNull() || n.isMissingNode()) ? null : n.asText();
    }

    private static Long longOrNull(JsonNode node, String field) {
        JsonNode n = node.get(field);
        if (n == null || n.isNull() || n.isMissingNode()) {
            return null;
        }
        return n.isNumber() ? n.asLong() : null;
    }
}
