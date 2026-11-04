package com.vaultix.common.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class MaskUtil {

    private static final String MASK_REPLACEMENT = "***";

    private MaskUtil() {
    }

    /**
     * Masks an email address for privacy and security previews (e.g.,
     * v***l@gmail.com).
     *
     * @param email raw email string
     * @return masked email or empty string if input is null or blank
     */
    public static String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return "";
        }

        String clean = email.strip();
        int atIndex = clean.indexOf('@');
        if (atIndex <= 0 || atIndex == clean.length() - 1) {
            return clean;
        }

        String localPart = clean.substring(0, atIndex);
        String domainPart = clean.substring(atIndex + 1);

        if (localPart.length() == 1) {
            return localPart + MASK_REPLACEMENT + "@" + domainPart;
        }

        if (localPart.length() == 2) {
            return localPart.charAt(0) + MASK_REPLACEMENT + localPart.charAt(1) + "@" + domainPart;
        }

        return localPart.charAt(0) + MASK_REPLACEMENT + localPart.charAt(localPart.length() - 1) + "@" + domainPart;
    }

    /**
     * Masks a phone number retaining only the last 2 digits matching Google
     * Account security standards (e.g., +91 ••••••89 or ••••••89).
     *
     * @param phone raw phone number string
     * @return masked phone number or empty string if input is null or blank
     */
    public static String maskPhone(String phone) {
        if (phone == null || phone.isBlank()) {
            return "";
        }

        String clean = phone.strip();
        if (clean.length() <= 2) {
            return clean;
        }

        /* Match optional country code (+XX or +XXX) followed by digits */
        Matcher matcher = Pattern.compile("^(\\+\\d{1,4})\\s*(.*)$").matcher(clean);
        if (matcher.matches()) {
            String countryCode = matcher.group(1);
            String rest = matcher.group(2).replaceAll("\\s+", "");
            if (rest.length() > 2) {
                String lastTwo = rest.substring(rest.length() - 2);
                return countryCode + " ••••••" + lastTwo;
            }
        }

        String lastTwo = clean.substring(clean.length() - 2);
        return "••••••" + lastTwo;
    }

    /**
     * Alias for {@link #maskPhone(String)} to support phone number masking.
     *
     * @param phone raw phone number string
     * @return masked phone number or empty string if input is null or blank
     */
    public static String maskPhoneNumber(String phone) {
        return maskPhone(phone);
    }

    /**
     * Masks a username for privacy and security previews (e.g., v***l). If the
     * input contains an '@' character, delegates to maskEmail.
     *
     * @param username raw username string
     * @return masked username or empty string if input is null or blank
     */
    public static String maskUsername(String username) {
        if (username == null || username.isBlank()) {
            return "";
        }

        String clean = username.strip();
        if (clean.contains("@")) {
            return maskEmail(clean);
        }

        if (clean.length() == 1) {
            return clean + MASK_REPLACEMENT;
        }

        if (clean.length() == 2) {
            return clean.charAt(0) + MASK_REPLACEMENT + clean.charAt(1);
        }

        return clean.charAt(0) + MASK_REPLACEMENT + clean.charAt(clean.length() - 1);
    }
}
