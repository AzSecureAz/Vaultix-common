package com.vaultix.common.util;

import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

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
     */
    public static void subscribe(
            RedisMessageListenerContainer container,
            String topicName,
            Consumer<String> onMessage) {

        container.addMessageListener((message, pattern) -> {
            String payload = new String(message.getBody(), StandardCharsets.UTF_8);
            onMessage.accept(payload);
        }, new ChannelTopic(topicName));
    }
}
