package com.vaultix.common.dto.notification;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record NotificationEvent(
        @NotNull(message = "Event ID is required")
        UUID eventId,
        @NotBlank(message = "Template code is required")
        @Size(max = 128, message = "Template code cannot exceed 128 characters")
        @Pattern(
                regexp = "^[a-z0-9]+([._-][a-z0-9]+)*$",
                message = "Template code must contain only lowercase alphanumeric characters separated by dots, hyphens, or underscores"
        )
        String templateCode,
        @NotNull(message = "Notification channel is required")
        NotificationChannel channel,
        @NotBlank(message = "Recipient is required")
        @Size(max = 256, message = "Recipient cannot exceed 256 characters")
        String recipient,
        @NotBlank(message = "Recipient name is required")
        @Size(max = 256, message = "Recipient name cannot exceed 256 characters")
        String recipientName,
        @NotBlank(message = "Subject is required")
        @Size(max = 256, message = "Subject cannot exceed 256 characters")
        String subject,
        @NotNull(message = "Params map is required")
        Map<String, Object> params,
        @NotNull(message = "Creation timestamp is required")
        Instant createdAt) {

}
