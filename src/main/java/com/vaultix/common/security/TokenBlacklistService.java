package com.vaultix.common.security;

import java.time.Duration;
import java.util.Collection;

public interface TokenBlacklistService {

    String KEY_PREFIX = "auth:blacklist:";

    void blacklist(String jti, Duration ttl);

    default void blacklist(String jti, long ttlSeconds) {
        blacklist(jti, Duration.ofSeconds(ttlSeconds));
    }

    void blacklistAll(Collection<String> jtis, Duration ttl);

    default void blacklistAll(Collection<String> jtis, long ttlSeconds) {
        blacklistAll(jtis, Duration.ofSeconds(ttlSeconds));
    }

    boolean isBlacklisted(String jti);
}
