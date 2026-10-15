package com.vaultix.common.security;

import java.time.Duration;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class NoOpTokenBlacklistService implements TokenBlacklistService {

    @Override
    public void blacklist(String jti, Duration ttl) {
        log.debug("No-op token blacklist invoked for jti: {} (Redis not available)", jti);
    }

    @Override
    public boolean isBlacklisted(String jti) {
        return false;
    }
}
