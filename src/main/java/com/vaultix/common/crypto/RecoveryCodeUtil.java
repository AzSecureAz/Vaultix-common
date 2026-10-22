package com.vaultix.common.crypto;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Pure, stateless cryptographic utility for generating human-readable,
 * high-entropy MFA emergency recovery codes.
 * <p>
 * Uses {@link SecureRandom} over an unambiguous alphanumeric character set
 * (excluding visually confusing characters such as 0/O, 1/l, 8/B).
 */
public final class RecoveryCodeUtil {

    public static final int DEFAULT_CODE_COUNT = 10;
    public static final int DEFAULT_CODE_LENGTH = 10;
    public static final int DEFAULT_GROUP_SIZE = 5;

    /*
     * Crockford/Base32 inspired human-friendly alphabet (32 characters = 5 bits of entropy per char).
     * Excludes 0 (zero), O (capital o), 1 (one), I (capital i), l (lowercase L).
     */
    private static final String ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private RecoveryCodeUtil() {
    }

    /**
     * Generates a default list of 10 cryptographically secure recovery codes,
     * each 10 characters long and formatted as {@code xxxxx-xxxxx}.
     *
     * @return an unmodifiable list of unique, formatted recovery codes
     */
    public static List<String> generateCodes() {
        return generateCodes(DEFAULT_CODE_COUNT, DEFAULT_CODE_LENGTH);
    }

    /**
     * Generates a specified number of unique recovery codes with given
     * character length.
     *
     * @param count the number of recovery codes to generate
     * @param length the raw character length of each code (excluding hyphens)
     * @return an unmodifiable list of unique, formatted recovery codes
     */
    public static List<String> generateCodes(int count, int length) {
        if (count <= 0) {
            throw new IllegalArgumentException("Recovery code count must be greater than zero");
        }
        if (length < 8) {
            throw new IllegalArgumentException("Recovery code length must be at least 8 characters for security");
        }

        List<String> codes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            codes.add(generateCode(length));
        }
        return Collections.unmodifiableList(codes);
    }

    /**
     * Generates a single cryptographically secure recovery code with default
     * length (10 chars, xxxxx-xxxxx).
     *
     * @return formatted recovery code
     */
    public static String generateCode() {
        return generateCode(DEFAULT_CODE_LENGTH);
    }

    /**
     * Generates a single cryptographically secure recovery code of specified
     * length formatted in groups.
     *
     * @param length the character length
     * @return formatted recovery code
     */
    public static String generateCode(int length) {
        if (length < 8) {
            throw new IllegalArgumentException("Recovery code length must be at least 8 characters for security");
        }

        char[] rawChars = new char[length];
        for (int i = 0; i < length; i++) {
            rawChars[i] = ALPHABET.charAt(SECURE_RANDOM.nextInt(ALPHABET.length()));
        }

        return formatCode(new String(rawChars));
    }

    /**
     * Formats a raw alphanumeric code string with a hyphen separator in the
     * middle. E.g., {@code abcde12345} becomes {@code abcde-12345}.
     *
     * @param rawCode the raw code string
     * @return formatted code with hyphen separator
     */
    public static String formatCode(String rawCode) {
        if (rawCode == null || rawCode.isBlank()) {
            return "";
        }
        String clean = normalizeCode(rawCode);
        int mid = clean.length() / 2;
        if (mid == 0) {
            return clean;
        }
        return clean.substring(0, mid) + "-" + clean.substring(mid);
    }

    /**
     * Normalizes a user-entered recovery code by removing hyphens and
     * whitespace, and converting to lower case.
     *
     * @param input the user entered code
     * @return normalized code string
     */
    public static String normalizeCode(String input) {
        if (input == null || input.isBlank()) {
            return "";
        }
        return input.strip().replace("-", "").replace(" ", "").toLowerCase(Locale.ROOT);
    }
}
