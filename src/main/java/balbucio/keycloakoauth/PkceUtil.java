package balbucio.keycloakoauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PKCE (Proof Key for Code Exchange) utilities per RFC 7636.
 * Generates code_verifier and code_challenge (S256).
 */
public final class PkceUtil {

    private static final int CODE_VERIFIER_BYTES = 32;
    private static final String SHA_256 = "SHA-256";

    private PkceUtil() {
    }

    /**
     * Generates a cryptographically random code_verifier (43–128 characters, Base64-URL without padding).
     */
    public static String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[CODE_VERIFIER_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Generates the code_challenge from the code_verifier using S256 (SHA-256, Base64-URL without padding).
     * The verifier is hashed as US-ASCII bytes per RFC 7636.
     */
    public static String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] input = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            digest.update(input, 0, input.length);
            byte[] hash = digest.digest();
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
