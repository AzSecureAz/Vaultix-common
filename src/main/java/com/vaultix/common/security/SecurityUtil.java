package com.vaultix.common.security;

import java.util.UUID;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public final class SecurityUtil {

    private SecurityUtil() {
    }

    /**
     * Extracts the JWT token from the given Spring Security Authentication
     * object.
     *
     * @param authentication the authenticated principal
     * @return the extracted JWT token
     * @throws BadCredentialsException if the authentication is null or
     * principal is not a valid JWT
     */
    public static Jwt extractJwt(Authentication authentication) {
        if (authentication == null) {
            throw new BadCredentialsException("Authentication cannot be null");
        }
        if (authentication.getPrincipal() instanceof Jwt principalJwt) {
            return principalJwt;
        }
        if (authentication instanceof JwtAuthenticationToken jwtAuthToken) {
            return jwtAuthToken.getToken();
        }
        throw new BadCredentialsException("Authentication principal is not a valid JWT token");
    }

    /**
     * Extracts and validates the subject UUID (actor/user ID) directly from an
     * Authentication object.
     *
     * @param authentication the Spring Security Authentication object
     * @return the parsed actor UUID
     * @throws BadCredentialsException if authentication is invalid or subject
     * is missing/malformed
     */
    public static UUID extractActorId(Authentication authentication) {
        return extractActorId(extractJwt(authentication));
    }

    /**
     * Extracts and validates the session ID (sid claim) directly from an
     * Authentication object.
     *
     * @param authentication the Spring Security Authentication object
     * @return the parsed session UUID
     * @throws BadCredentialsException if authentication is invalid or sid claim
     * is missing/malformed
     */
    public static UUID extractSessionId(Authentication authentication) {
        return extractSessionId(extractJwt(authentication));
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

    /**
     * Extracts and validates the session ID (sid claim) from a JWT token.
     *
     * @param jwt the authenticated JWT token
     * @return the parsed session UUID
     * @throws BadCredentialsException if the token is null, sid claim is
     * missing/blank, or sid is not a valid UUID
     */
    public static UUID extractSessionId(Jwt jwt) {
        if (jwt == null) {
            throw new BadCredentialsException("Invalid or missing authentication token");
        }
        String sid = jwt.getClaimAsString("sid");
        if (sid == null || sid.isBlank()) {
            throw new BadCredentialsException("Missing session ID in authentication token");
        }
        try {
            return UUID.fromString(sid.strip());
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid session ID in authentication token");
        }
    }
}
