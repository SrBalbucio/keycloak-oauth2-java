package balbucio.keycloakoauth;

import io.javalin.Javalin;

/**
 * Use this to run the OAuth2 flow from tests or to create test-specific configurations
 * (e.g. different port, realm, or client). You can extend this class or add more test
 * entry points in the same package.
 */
public class KeycloakOAuth2MainForTests {

    public static void main(String[] args) {
        KeycloakAuthConfig config = KeycloakAuthConfig.builder()
                .baseUrl("http://localhost:8080")
                .realm("master")
                .clientId("my-app")
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
                    provider.startLogin();
                    ctx.html("<html><head><meta charset=\"UTF-8\"><title>Redirecting</title></head><body>" +
                            "<p>Opening Keycloak login in your browser. If it did not open, " +
                            "<a href=\"" + config.getAuthorizationEndpoint() + "\">click here</a>.</p>" +
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
