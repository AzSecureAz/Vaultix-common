package com.vaultix.common.security;

import java.time.Duration;

public interface TokenBlacklistService {

    void blacklist(String jti, Duration ttl);

    default void blacklist(String jti, long ttlSeconds) {
        blacklist(jti, Duration.ofSeconds(ttlSeconds));
    }

    boolean isBlacklisted(String jti);
}
