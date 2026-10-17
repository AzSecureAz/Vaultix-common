package com.vaultix.common.security;

import java.time.Instant;

public interface PermissionRevocationService {

    String KEY = "auth:permission:disabled";

    void loadDisabledPermissionsIntoCache();

    void handleRevocationEvent(String eventPayload);

    boolean isRevoked(String permission, Instant issuedAt);
}
