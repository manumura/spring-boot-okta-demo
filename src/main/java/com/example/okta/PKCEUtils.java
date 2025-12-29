package com.example.okta;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PKCEUtils {

    /**
     * Generates a secure random string (code verifier) between 43 and 128 characters long.
     * @return A random code verifier value.
     */
    public static String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[32]; // 32 bytes = 256 bits of entropy
        secureRandom.nextBytes(bytes);
        // Base64 URL encode the bytes and remove padding
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Generates a code challenge from a code verifier using SHA-256 and Base64 URL encoding.
     * @param codeVerifierValue The random string code verifier value.
     * @return An encoded code challenge string value.
     * @throws NoSuchAlgorithmException If SHA-256 is not available.
     * @throws UnsupportedEncodingException If US-ASCII encoding is not available.
     */
    public static String generateCodeChallenge(String codeVerifierValue)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] bytes = codeVerifierValue.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digest = messageDigest.digest(bytes);
        // Base64 URL encode the digest and remove padding
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}

