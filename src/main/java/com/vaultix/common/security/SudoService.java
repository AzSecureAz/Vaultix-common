package com.vaultix.common.security;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

public interface SudoService {

    String KEY_PREFIX = "sudo:session:";
    Duration DEFAULT_SUDO_DURATION = Duration.ofMinutes(5);

    /**
     * Elevates sudo privileges for the specified session ID with a custom TTL.
     *
     * @param sessionId the unique session ID (refresh token JTI)
     * @param ttl the elevation duration
     */
    void elevateSudo(UUID sessionId, Duration ttl);

    /**
     * Elevates sudo privileges for the specified session ID with the default
     * duration (5 minutes).
     *
     * @param sessionId the unique session ID (refresh token JTI)
     */
    default void elevateSudo(UUID sessionId) {
        elevateSudo(sessionId, DEFAULT_SUDO_DURATION);
    }

    /**
     * Checks if sudo elevation is currently active for the specified session
     * ID.
     *
     * @param sessionId the unique session ID
     * @return true if sudo is active and not expired, false otherwise
     */
    boolean isSudoActive(UUID sessionId);

    /**
     * Checks if sudo elevation is currently active and within the specified
     * maximum age.
     *
     * @param sessionId the unique session ID
     * @param maxAgeSeconds the maximum age in seconds since elevation
     * @return true if sudo is active and elevated within maxAgeSeconds, false
     * otherwise
     */
    boolean isSudoActive(UUID sessionId, long maxAgeSeconds);

    /**
     * Revokes sudo privileges for the specified session ID immediately.
     *
     * @param sessionId the unique session ID
     */
    void revokeSudo(UUID sessionId);

    /**
     * Returns the remaining duration in seconds for the active sudo elevation.
     *
     * @param sessionId the unique session ID
     * @return remaining seconds if active, or empty if expired/inactive
     */
    Optional<Long> getRemainingSeconds(UUID sessionId);
}
