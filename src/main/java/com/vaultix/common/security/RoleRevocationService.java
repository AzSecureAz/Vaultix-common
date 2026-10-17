package com.vaultix.common.security;

import java.time.Instant;

public interface RoleRevocationService {

    String KEY = "auth:role:disabled";

    void loadDisabledRolesIntoCache();

    void handleRevocationEvent(String eventPayload);

    boolean isRevoked(String role, Instant issuedAt);
}
