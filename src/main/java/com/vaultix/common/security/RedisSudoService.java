package com.vaultix.common.security;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.StringRedisTemplate;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Builder
@AllArgsConstructor
public class RedisSudoService implements SudoService {

    @NonNull
    private final StringRedisTemplate stringRedisTemplate;

    @Override
    public void elevateSudo(UUID sessionId, Duration ttl) {
        if (sessionId == null) {
            log.warn("Attempted to elevate sudo with null sessionId");
            return;
        }

        Duration effectiveTtl = (ttl != null && !ttl.isNegative() && !ttl.isZero()) ? ttl : DEFAULT_SUDO_DURATION;
        String key = KEY_PREFIX + sessionId;
        stringRedisTemplate.opsForValue().set(key, Instant.now().toString(), effectiveTtl);
        log.info("Elevated sudo for session ID: {} with duration: {}s", sessionId, effectiveTtl.toSeconds());
    }

    @Override
    public boolean isSudoActive(UUID sessionId) {
        if (sessionId == null) {
            return false;
        }

        String key = KEY_PREFIX + sessionId;
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(key));
    }

    @Override
    public boolean isSudoActive(UUID sessionId, long maxAgeSeconds) {
        if (sessionId == null) {
            return false;
        }

        if (maxAgeSeconds <= 0) {
            return isSudoActive(sessionId);
        }

        String key = KEY_PREFIX + sessionId;
        String elevatedAtStr = stringRedisTemplate.opsForValue().get(key);
        if (elevatedAtStr == null || elevatedAtStr.isBlank()) {
            return false;
        }

        try {
            Instant elevatedAt = Instant.parse(elevatedAtStr.strip());
            Instant cutoff = Instant.now().minusSeconds(maxAgeSeconds);
            return !elevatedAt.isBefore(cutoff);
        } catch (DateTimeParseException e) {
            log.warn("Invalid timestamp format in sudo session key: {}", key);
            return false;
        }
    }

    @Override
    public void revokeSudo(UUID sessionId) {
        if (sessionId == null) {
            return;
        }

        String key = KEY_PREFIX + sessionId;
        Boolean deleted = stringRedisTemplate.delete(key);
        if (Boolean.TRUE.equals(deleted)) {
            log.info("Revoked sudo elevation for session ID: {}", sessionId);
        }
    }

    @Override
    public Optional<Long> getRemainingSeconds(UUID sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }

        String key = KEY_PREFIX + sessionId;
        Long expire = stringRedisTemplate.getExpire(key, TimeUnit.SECONDS);
        if (expire == null || expire <= 0) {
            return Optional.empty();
        }

        return Optional.of(expire);
    }
}
