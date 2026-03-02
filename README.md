# Keycloak OAuth2 (Authorization Code + PKCE)
[![](https://img.shields.io/badge/HyperPowered-Use%20the%20official%20repository-yellow?color=%23279BF8&cacheSeconds=3600)](https://maven.dev.hyperpowered.net/#/releases/balbucio/keycloakoauth/keycloak-oauth2-java/)

Provedor mínimo de autenticação OAuth2 **Authorization Code + PKCE** para Keycloak. Abre o login no navegador, escuta o callback em localhost com um servidor Javalin e troca o código por tokens.

- **Java 8+**
- **Javalin 4.6.x** (servidor HTTP)
- **PKCE** (code_verifier / code_challenge S256)
- Servidor permanece aberto; várias rodadas de login sem reiniciar
---

## Pré-requisitos

- **JDK 8** (ou superior)
- **Maven 3.x**
- **Keycloak** rodando (ex.: `http://localhost:8080`) com um realm e um client configurado

---

## Configuração no Keycloak

1. Acesse o **Keycloak Admin** (ex.: `http://localhost:8080/admin`).
2. Crie ou escolha um **realm** (ex.: `master` ou `myrealm`).
3. Em **Clients**, crie um client (ex.: `my-app`) ou edite um existente:
   - **Client authentication**: desligado (public client).
   - **Valid redirect URIs**: inclua exatamente a URL do callback, por exemplo:
     - `http://localhost:8765/callback`
   - **Web origins**: pode usar `+` ou `http://localhost:8765` se precisar de CORS.
4. Salve.

A URL de callback deve ser **exatamente** a que a aplicação usa (incluindo porta e path `/callback`).

---

## Configuração da aplicação

No builder de `KeycloakAuthConfig`:

| Parâmetro     | Default               | Descrição                          |
|---------------|-----------------------|------------------------------------|
| `baseUrl`     | `http://localhost:8080` | URL base do Keycloak             |
| `realm`       | `master`              | Nome do realm                      |
| `clientId`    | `my-app`              | Client ID do Keycloak              |
| `redirectPort`| `8765`                | Porta do servidor local e do callback |
| `scope`       | `openid`              | Escopos OAuth2                     |

Exemplo de alteração:

```java
KeycloakAuthConfig config = KeycloakAuthConfig.builder()
    .baseUrl("http://localhost:8080")
    .realm("myrealm")
    .clientId("meu-client")
    .redirectPort(8765)
    .scope("openid")
    .build();

KeycloakAuthProvider provider = new KeycloakAuthProvider(config);
CallbackHandler callbackHandler = new CallbackHandler(provider);
```

O `redirect_uri` usado na autorização e na troca de tokens é sempre `http://localhost:{redirectPort}/callback` e deve ser o mesmo configurado em **Valid redirect URIs** no client do Keycloak.

---