package com.vaultix.common.util;

import java.util.Optional;
import java.util.UUID;

public final class UuidUtils {

    private UuidUtils() {
    }

    public static boolean isPotentialUuid(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            boolean isHyphen = (c == '-');
            if (!isHex && !isHyphen) {
                return false;
            }
        }
        return true;
    }

    public static boolean isUuid(String value) {
        return parseUuid(value).isPresent();
    }

    public static Optional<UUID> parseUuid(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(UUID.fromString(value.strip()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
