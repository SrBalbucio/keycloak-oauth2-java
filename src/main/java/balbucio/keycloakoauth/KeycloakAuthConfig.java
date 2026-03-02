package balbucio.keycloakoauth;

import lombok.Builder;
import lombok.Value;

/**
 * Configuration for the Keycloak OAuth2 client (Authorization Code + PKCE).
 */
@Value
@Builder
public class KeycloakAuthConfig {

    /** Base URL of the Keycloak server (e.g. http://localhost:8080). */
    String baseUrl;

    /** Realm name (e.g. master or myrealm). */
    String realm;

    /** Keycloak client ID. */
    String clientId;

    /** Port for the local callback server (redirect_uri will be http://localhost:{redirectPort}/callback). */
    int redirectPort;

    /** OAuth2 scope. Defaults to "openid" if not set. */
    @Builder.Default
    String scope = "openid";
    @Builder.Default
    boolean devMode = false;

    /**
     * Builds the redirect URI for this config.
     */
    public String getRedirectUri() {
        return "http://localhost:" + redirectPort + "/callback";
    }

    /**
     * Builds the authorization endpoint URL (without query string).
     */
    public String getAuthorizationEndpoint() {
        return baseUrl.replaceAll("/$", "") + "/realms/" + realm + "/protocol/openid-connect/auth";
    }

    /**
     * Builds the token endpoint URL.
     */
    public String getTokenEndpoint() {
        return baseUrl.replaceAll("/$", "") + "/realms/" + realm + "/protocol/openid-connect/token";
    }
}
