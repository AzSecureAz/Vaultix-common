package com.vaultix.common.util;

import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.util.Assert;

import lombok.Builder;
import lombok.NonNull;

public final class RedisPubSubHelper {

    private RedisPubSubHelper() {
    }

    /**
     * Subscribes a lambda callback to a Redis channel topic.
     *
     * @param container the Redis message listener container
     * @param topicName the Redis channel topic name
     * @param onMessage the callback to invoke with the decoded UTF-8 message
     * payload
     * @return the Redis message listener container
     */
    @Builder
    public static RedisMessageListenerContainer subscribe(
            @NonNull RedisMessageListenerContainer container,
            String topicName,
            @NonNull Consumer<String> onMessage) {

        Assert.hasText(topicName, "topicName must not be null or blank");

        container.addMessageListener((message, pattern) -> {
            String payload = new String(message.getBody(), StandardCharsets.UTF_8);
            onMessage.accept(payload);
        }, new ChannelTopic(topicName));

        return container;
    }
}
