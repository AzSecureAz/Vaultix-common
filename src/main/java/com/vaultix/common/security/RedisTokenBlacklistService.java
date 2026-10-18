package com.vaultix.common.security;

import java.time.Duration;

import org.springframework.data.redis.core.StringRedisTemplate;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Builder
@AllArgsConstructor
public class RedisTokenBlacklistService implements TokenBlacklistService {

    @NonNull
    private final StringRedisTemplate stringRedisTemplate;

    @Override
    public void blacklist(String jti, Duration ttl) {
        if (jti == null || jti.isBlank()) {
            return;
        }
        String cleanedJti = jti.strip();
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            log.debug("Skipping blacklisting for jti: {} with non-positive TTL", cleanedJti);
            return;
        }

        String key = KEY_PREFIX + cleanedJti;
        stringRedisTemplate.opsForValue().set(key, "revoked", ttl);
        log.info("Blacklisted token JTI: {} in Redis for duration: {}s", cleanedJti, ttl.toSeconds());
    }

    @Override
    public boolean isBlacklisted(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        String key = KEY_PREFIX + jti.strip();
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(key));
    }
}
