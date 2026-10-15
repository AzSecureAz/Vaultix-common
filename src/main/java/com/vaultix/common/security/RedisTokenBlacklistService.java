package com.vaultix.common.security;

import java.time.Duration;

import org.springframework.data.redis.core.StringRedisTemplate;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class RedisTokenBlacklistService implements TokenBlacklistService {

    public static final String KEY_PREFIX = "auth:blacklist:";

    private final StringRedisTemplate stringRedisTemplate;

    @Override
    public void blacklist(String jti, Duration ttl) {
        if (jti == null || jti.isBlank()) {
            return;
        }
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            log.debug("Skipping blacklisting for jti: {} with non-positive TTL", jti);
            return;
        }

        String key = KEY_PREFIX + jti.trim();
        stringRedisTemplate.opsForValue().set(key, "revoked", ttl);
        log.info("Blacklisted token JTI: {} in Redis for duration: {}s", jti, ttl.toSeconds());
    }

    @Override
    public boolean isBlacklisted(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        String key = KEY_PREFIX + jti.trim();
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(key));
    }
}
