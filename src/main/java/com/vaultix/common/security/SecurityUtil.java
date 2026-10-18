package com.vaultix.common.security;

import java.util.UUID;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.Jwt;

public final class SecurityUtil {

    private SecurityUtil() {
    }

    /**
     * Extracts and validates the subject UUID (actor/user ID) from a JWT token.
     *
     * @param jwt the authenticated JWT token
     * @return the parsed actor UUID
     * @throws BadCredentialsException if the token is null, subject is
     * missing/blank, or subject is not a valid UUID
     */
    public static UUID extractActorId(Jwt jwt) {
        if (jwt == null || jwt.getSubject() == null || jwt.getSubject().isBlank()) {
            throw new BadCredentialsException("Invalid or missing authentication token");
        }
        try {
            return UUID.fromString(jwt.getSubject().strip());
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid actor ID in authentication token");
        }
    }
}
