package balbucio.keycloakoauth;

import io.javalin.Javalin;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

/**
 * Use this to run the OAuth2 flow from tests or to create test-specific configurations
 * (e.g. different port, realm, or client). You can extend this class or add more test
 * entry points in the same package.
 */
public class KeycloakOAuth2MainForTests {

    public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) { }
            public void checkServerTrusted(X509Certificate[] certs, String authType) { }

        } };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HostnameVerifier allHostsValid = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        String keycloakUrl = System.getenv("KEYCLOAK_URL");
        String keycloakClientId = System.getenv("KEYCLOAK_CLIENT_ID");
        String keycloakRealm = System.getenv("KEYCLOAK_REALM");

        KeycloakAuthConfig config = KeycloakAuthConfig.builder()
                .baseUrl(keycloakUrl)
                .realm(keycloakRealm)
                .clientId(keycloakClientId)
                .redirectPort(8765)
                .scope("openid")
                .build();

        KeycloakAuthProvider provider = new KeycloakAuthProvider(config);
        CallbackHandler callbackHandler = new CallbackHandler(provider);

        Javalin app = Javalin.create()
                .get("/", ctx -> {
                    ctx.html("<html><head><meta charset=\"UTF-8\"><title>Keycloak OAuth2</title></head><body>" +
                            "<h1>Keycloak OAuth2 (Authorization Code + PKCE)</h1>" +
                            "<p><a href=\"/login\">Start login</a></p>" +
                            "</body></html>");
                })
                .get("/login", ctx -> {
                    ctx.html("<html><head><meta charset=\"UTF-8\"><title>Redirecting</title></head><body>" +
                            "<p>Opening Keycloak login in your browser. If it did not open, " +
                            "<a href=\"" + provider.startLogin() + "\">click here</a>.</p>" +
                            "</body></html>");
                })
                .get("/callback", ctx -> {
                    String code = ctx.queryParam("code");
                    String state = ctx.queryParam("state");
                    String error = ctx.queryParam("error");
                    String errorDescription = ctx.queryParam("error_description");
                    String html = callbackHandler.handleCallback(code, state, error, errorDescription);
                    ctx.contentType("text/html; charset=UTF-8").result(html);
                });

        System.out.println("Callback server: http://localhost:" + config.getRedirectPort());
        System.out.println("Open http://localhost:" + config.getRedirectPort() + "/login to start the flow.");
        app.start(config.getRedirectPort());
    }
}
