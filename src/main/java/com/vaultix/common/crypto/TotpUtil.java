package com.vaultix.common.crypto;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;
import java.util.OptionalLong;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure, stateless cryptographic utility for Time-Based One-Time Passwords
 * (TOTP) compliant with RFC 6238, RFC 4226 (HOTP), and the Google Authenticator
 * URI specification.
 * <p>
 * Built with zero external dependencies, using native JDK
 * {@code javax.crypto.Mac} and native RFC 4648 Base32 encoding/decoding.
 */
public final class TotpUtil {

    public static final String DEFAULT_HMAC_ALGORITHM = "HmacSHA1";
    public static final int DEFAULT_DIGITS = 6;
    public static final int DEFAULT_PERIOD_SECONDS = 30;
    public static final int DEFAULT_SECRET_BYTES = 20;
    /* 160 bits (RFC 4226 recommended) */
    public static final int DEFAULT_WINDOW = 1;
    /* ±1 step (30 seconds before/after) */

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private TotpUtil() {
    }

    /**
     * Generates a cryptographically secure 160-bit (20 bytes) Base32-encoded
     * secret key without padding.
     */
    public static String generateSecret() {
        return generateSecret(DEFAULT_SECRET_BYTES);
    }

    /**
     * Generates a cryptographically secure Base32-encoded secret key of
     * specified byte length without padding.
     */
    public static String generateSecret(int numBytes) {
        if (numBytes < 10) {
            throw new IllegalArgumentException("Secret key length must be at least 10 bytes (80 bits) for security");
        }
        byte[] bytes = new byte[numBytes];
        SECURE_RANDOM.nextBytes(bytes);
        return base32Encode(bytes);
    }

    /**
     * Calculates the current time step based on the epoch second and given
     * period.
     */
    public static long calculateStep(Instant instant, int periodSeconds) {
        if (periodSeconds <= 0) {
            throw new IllegalArgumentException("Period must be greater than zero");
        }
        return (instant != null ? instant.getEpochSecond() : Instant.now().getEpochSecond()) / periodSeconds;
    }

    /**
     * Calculates the current time step for the standard 30-second window.
     */
    public static long calculateStep() {
        return calculateStep(Instant.now(), DEFAULT_PERIOD_SECONDS);
    }

    /**
     * Generates a TOTP code for a specific time step using default parameters
     * (6 digits, HmacSHA1).
     */
    public static String generateCode(String base32Secret, long timeStep) {
        return generateCode(base32Secret, timeStep, DEFAULT_DIGITS, DEFAULT_HMAC_ALGORITHM);
    }

    /**
     * Generates a TOTP code for a specific time step according to RFC 6238 /
     * RFC 4226.
     */
    public static String generateCode(String base32Secret, long timeStep, int digits, String hmacAlgorithm) {
        if (base32Secret == null || base32Secret.isBlank()) {
            throw new IllegalArgumentException("Base32 secret must not be null or blank");
        }
        if (digits != 6 && digits != 8) {
            throw new IllegalArgumentException("TOTP digits must be either 6 or 8");
        }
        String algorithm = (hmacAlgorithm != null && !hmacAlgorithm.isBlank()) ? hmacAlgorithm : DEFAULT_HMAC_ALGORITHM;

        byte[] keyBytes = base32Decode(base32Secret);
        if (keyBytes.length == 0) {
            throw new IllegalArgumentException("Invalid Base32 secret key");
        }

        byte[] data = ByteBuffer.allocate(8).putLong(timeStep).array();

        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(keyBytes, algorithm));
            byte[] hash = mac.doFinal(data);

            /* Dynamic Truncation (RFC 4226 Section 5.3) */
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int modulo = (int) Math.pow(10, digits);
            int otp = binary % modulo;

            return String.format(Locale.ROOT, "%0" + digits + "d", otp);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to calculate HMAC for TOTP", e);
        }
    }

    /**
     * Verifies a user-provided TOTP code against the current timestamp with
     * default window (±1).
     */
    public static boolean verifyCode(String base32Secret, String code) {
        return verifyCodeAndGetStep(base32Secret, code, calculateStep(), DEFAULT_WINDOW, DEFAULT_DIGITS, DEFAULT_PERIOD_SECONDS, DEFAULT_HMAC_ALGORITHM).isPresent();
    }

    /**
     * Verifies a user-provided TOTP code with configurable window tolerance and
     * returns the matched time step. Returning the matched step enables the
     * caller to prevent replay attacks by verifying
     * {@code step > lastUsedStep}.
     */
    public static OptionalLong verifyCodeAndGetStep(
            String base32Secret,
            String code,
            long currentStep,
            int window,
            int digits,
            int periodSeconds,
            String hmacAlgorithm) {

        if (base32Secret == null || base32Secret.isBlank() || code == null || code.isBlank()) {
            return OptionalLong.empty();
        }

        String cleanCode = code.strip();
        if (cleanCode.length() != digits) {
            return OptionalLong.empty();
        }

        for (int i = -window; i <= window; i++) {
            long step = currentStep + i;
            String expectedCode = generateCode(base32Secret, step, digits, hmacAlgorithm);

            /* Constant-time comparison to prevent side-channel timing attacks */
            if (MessageDigest.isEqual(
                    expectedCode.getBytes(StandardCharsets.UTF_8),
                    cleanCode.getBytes(StandardCharsets.UTF_8))) {
                return OptionalLong.of(step);
            }
        }

        return OptionalLong.empty();
    }

    /**
     * Generates a standard Google Authenticator compatible Key URI
     * (otpauth://).
     */
    public static String generateOtpAuthUri(String issuer, String accountName, String base32Secret) {
        return generateOtpAuthUri(issuer, accountName, base32Secret, DEFAULT_DIGITS, DEFAULT_PERIOD_SECONDS, "SHA1");
    }

    /**
     * Generates a standard Google Authenticator compatible Key URI with custom
     * parameters.
     */
    public static String generateOtpAuthUri(
            String issuer,
            String accountName,
            String base32Secret,
            int digits,
            int periodSeconds,
            String algorithmName) {

        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("Issuer must not be null or blank");
        }
        if (accountName == null || accountName.isBlank()) {
            throw new IllegalArgumentException("Account name must not be null or blank");
        }
        if (base32Secret == null || base32Secret.isBlank()) {
            throw new IllegalArgumentException("Secret must not be null or blank");
        }

        String encodedIssuer = urlEncode(issuer.strip());
        String encodedAccount = urlEncode(accountName.strip());
        String cleanSecret = base32Secret.toUpperCase(Locale.ROOT).replaceAll("[^A-Z2-7]", "");
        String cleanAlgorithm = (algorithmName != null && !algorithmName.isBlank()) ? algorithmName.strip().toUpperCase(Locale.ROOT) : "SHA1";

        return String.format(Locale.ROOT,
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
                encodedIssuer,
                encodedAccount,
                cleanSecret,
                encodedIssuer,
                cleanAlgorithm,
                digits,
                periodSeconds);
    }

    /**
     * Native RFC 4648 Base32 encoding without padding.
     */
    public static String base32Encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder result = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                result.append(BASE32_ALPHABET.charAt(index));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            result.append(BASE32_ALPHABET.charAt(index));
        }
        return result.toString();
    }

    /**
     * Native RFC 4648 Base32 decoding, lenient to spaces and case.
     */
    public static byte[] base32Decode(String base32) {
        if (base32 == null || base32.isBlank()) {
            return new byte[0];
        }
        String clean = base32.toUpperCase(Locale.ROOT).replaceAll("[^A-Z2-7]", "");
        ByteArrayOutputStream out = new ByteArrayOutputStream((clean.length() * 5) / 8);
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < clean.length(); i++) {
            char c = clean.charAt(i);
            int val = (c >= 'A' && c <= 'Z') ? (c - 'A') : (c - '2' + 26);
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return out.toByteArray();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
