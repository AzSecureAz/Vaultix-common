package com.vaultix.common.security;

import java.time.Duration;
import java.util.Collection;
import java.util.List;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
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
    public void blacklistAll(Collection<String> jtis, Duration ttl) {
        if (jtis == null || jtis.isEmpty() || ttl == null || ttl.isNegative() || ttl.isZero()) {
            return;
        }

        List<String> validKeys = jtis.stream()
                .filter(jti -> jti != null && !jti.isBlank())
                .map(jti -> KEY_PREFIX + jti.strip())
                .toList();

        if (validKeys.isEmpty()) {
            return;
        }

        stringRedisTemplate.executePipelined(new SessionCallback<Object>() {
            @Override
            public <K, V> Object execute(RedisOperations<K, V> operations) throws DataAccessException {
                @SuppressWarnings("unchecked")
                RedisOperations<String, String> stringOps = (RedisOperations<String, String>) operations;
                for (String key : validKeys) {
                    stringOps.opsForValue().set(key, "revoked", ttl);
                }
                return null;
            }
        });

        log.info("Batch-blacklisted {} token JTIs in Redis via pipelining (TTL: {}s)", validKeys.size(), ttl.toSeconds());
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
