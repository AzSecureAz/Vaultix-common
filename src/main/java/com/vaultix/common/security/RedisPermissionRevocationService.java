package com.vaultix.common.security;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.redis.core.StringRedisTemplate;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RedisPermissionRevocationService implements PermissionRevocationService, ApplicationRunner {

    private final StringRedisTemplate stringRedisTemplate;
    private final Cache<String, Instant> cache;

    public RedisPermissionRevocationService(StringRedisTemplate stringRedisTemplate) {
        this(stringRedisTemplate, Caffeine.newBuilder()
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .maximumSize(10_000)
                .build());
    }

    public RedisPermissionRevocationService(
            StringRedisTemplate stringRedisTemplate,
            Cache<String, Instant> cache) {
        this.stringRedisTemplate = Objects.requireNonNull(stringRedisTemplate, "stringRedisTemplate must not be null");
        this.cache = Objects.requireNonNull(cache, "cache must not be null");
    }

    @Override
    public void run(ApplicationArguments args) {
        log.info("Checking disabled permissions in Redis on startup...");
        loadDisabledPermissionsIntoCache();
    }

    @Override
    public void loadDisabledPermissionsIntoCache() {
        try {
            Map<Object, Object> entries = stringRedisTemplate.opsForHash().entries(KEY);
            if (entries.isEmpty()) {
                log.info("No disabled permissions found in Redis.");
                return;
            }

            for (Map.Entry<Object, Object> entry : entries.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    String permission = entry.getKey().toString().strip().toLowerCase(Locale.ROOT);
                    Instant disabledAt;
                    try {
                        disabledAt = Instant.parse(entry.getValue().toString());
                    } catch (Exception e) {
                        disabledAt = Instant.now();
                    }
                    cache.put(permission, disabledAt);
                }
            }
            log.info("Loaded {} disabled permission(s) from Redis into local cache.", entries.size());
        } catch (Exception e) {
            log.warn("Failed to load disabled permissions from Redis on startup: {}", e.getMessage());
        }
    }

    @Override
    public void handleRevocationEvent(String eventPayload) {
        if (eventPayload == null || eventPayload.isBlank()) {
            return;
        }

        String normalizedPermission = eventPayload.strip().toLowerCase(Locale.ROOT);
        log.info("Received permission revocation event for '{}'. Fetching state from Redis...", normalizedPermission);

        try {
            Object value = stringRedisTemplate.opsForHash().get(KEY, normalizedPermission);
            if (value != null) {
                Instant disabledAt;
                try {
                    disabledAt = Instant.parse(value.toString());
                } catch (Exception e) {
                    disabledAt = Instant.now();
                }
                cache.put(normalizedPermission, disabledAt);
                log.info("Cached disabled permission '{}' (disabledAt: {})", normalizedPermission, disabledAt);
            }
        } catch (Exception e) {
            log.warn("Failed to process permission revocation event for '{}': {}", normalizedPermission, e.getMessage());
        }
    }

    @Override
    public boolean isRevoked(String permission, Instant issuedAt) {
        if (permission == null || permission.isBlank()) {
            return false;
        }

        String normalizedPermission = permission.strip().toLowerCase(Locale.ROOT);
        Instant disabledAt = cache.getIfPresent(normalizedPermission);

        if (disabledAt == null) {
            return false;
        }

        return issuedAt == null || issuedAt.isBefore(disabledAt);
    }
}
