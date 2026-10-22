# Vaultix Common Library

The shared core library for the **Vaultix** microservices platform, providing cross-cutting concerns, client context utilities, unified API envelopes, centralized exception handling, cryptographic helpers, Redis pub/sub tooling, and the complete Spring Security resource server suite.

---

## Library Details

| Attribute | Value |
| :--- | :--- |
| **Group ID** | `com.vaultix` |
| **Artifact ID** | `common` |
| **Version** | `0.0.1` |
| **Runtime** | Java 27 (Amazon Corretto) |
| **Packaging** | Reusable Library JAR (installed to local `.m2` repository) |

---

## Core Capabilities & Modules

### 1. Unified API Response (`ApiResponse<T>`)
An immutable Java 27 `record` decorated with `@Builder` returning standardized JSON envelopes across all microservices:
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { ... },
  "timestamp": "2026-10-19T12:00:00Z",
  "errors": {
    "field": "error message"
  }
}
```
- **UTC Timestamp**: Uses standard ISO-8601 UTC `Instant` (e.g. `2026-10-19T12:00:00Z`).
- **Compact Constructor**: Automatically defaults `timestamp = Instant.now()` if not explicitly provided during direct instantiation or builder calls.
- **Factory Helpers**:
  - `ApiResponse.success(data)` / `ApiResponse.success(message, data)`
  - `ApiResponse.error(message)` / `ApiResponse.error(message, Map<String, String> errors)`
- **Fluent Builder**:
  ```java
  ApiResponse<UserDto> response = ApiResponse.<UserDto>builder()
          .success(true)
          .message("User fetched")
          .data(userDto)
          .build();
  ```

---

### 2. Centralized Exception Handling (`BaseGlobalExceptionHandler`, `BadRequestException`, etc.)
An extensible base `@RestControllerAdvice` class for all downstream services to inherit consistent, secure error responses:

- **`MethodArgumentNotValidException`**: Catches `@Valid @RequestBody` DTO validation failures and maps field and global errors into the `errors` map (`400 Bad Request`).
- **`HandlerMethodValidationException`**: Catches Spring 6.1+ native controller method parameter validation failures (e.g., `@RequestParam`, `@PathVariable`, `@CookieValue`) (`400 Bad Request`).
- **`ConstraintViolationException`**: Catches service-layer `@Validated` AOP proxy validation violations (`400 Bad Request`).
- **`MethodArgumentTypeMismatchException`**: Sanitizes type conversion failures into clear descriptive field error messages (`400 Bad Request`).
- **`HttpMessageNotReadableException`**: Replaces raw Jackson parser exceptions with `"Malformed JSON request body"` (`400 Bad Request`).
- **`AuthenticationException`**: Replaces raw authentication errors with `"Authentication required"`. Critically masks `InternalAuthenticationServiceException` as `"Authentication failed"` to prevent leaking database or backend connection details (`401 Unauthorized`).
- **`AccessDeniedException`**: Emits `403 Forbidden` with `"Access denied: You do not have permission to access this resource"`.
- **`BadRequestException`**: Runtime exception thrown for business-level validation errors, returning `400 Bad Request`.
- **`ResourceNotFoundException`**: Runtime exception thrown when a requested entity is missing, returning `404 Not Found`.
- **`ResourceConflictException`**: Runtime exception thrown for state or identity conflicts (e.g. duplicate username/email), returning `409 Conflict`.
- **`SNAKE_CASE` Error Alignment**: Converts all validation field names and violation property paths to `snake_case` using a cached linear transformation (`SNAKE_CASE_CACHE` via `ConcurrentHashMap`), ensuring error keys strictly match the platform's JSON naming strategy without relying on reflection.
- **Unhandled Exceptions**: Replaces unhandled exceptions with a generic `500 Internal Server Error`, hiding sensitive server stack traces from API clients.


---

### 3. Client Context Resolution (`ClientContextUtil`)
Extracts and sanitizes headers injected downstream by the API Gateway:
- **`X-Client-IP`**: Client's public IP address.
- **`X-Device-Info`**: Browser and operating system summary.
- **`X-Device-Location`**: Resolved geographic location (e.g., `City, Country`).
- **`ClientContext` Record**: Strongly typed record with `@Builder` and a compact constructor guaranteeing non-null, non-blank values (defaults to `"Unknown"`):
  ```java
  ClientContext context = ClientContextUtil.extract(httpRequest);

  /* Or via builder: */
  ClientContext custom = ClientContext.builder().ip("192.168.1.1").build();

  /* Or zero-allocation empty constant: */
  ClientContext empty = ClientContext.EMPTY;
  ```

---

### 4. Cryptographic Utilities (`AesGcmCryptoUtil`, `TotpUtil` & `RecoveryCodeUtil`)
- **`AesGcmCryptoUtil`**: Authenticated encryption using standard **AES-256 GCM**:
  - Secure 12-byte IV generation per encryption operation.
  - Constant-time MAC authentication verification against tampering.
  - Base64-encoded URL-safe payloads.
- **`TotpUtil`**: Stateless, pure Java implementation of **RFC 6238 (TOTP)** and **RFC 4226 (HOTP)**:
  - Generates cryptographically secure 160-bit Base32 secrets.
  - Native RFC 4648 Base32 encoding and decoding with zero external dependencies.
  - Formats standard `otpauth://totp/...` URIs for Google Authenticator / 1Password.
  - Constant-time code verification with configurable window tolerance and replay protection (`verifyCodeAndGetStep`).
- **`RecoveryCodeUtil`**: High-entropy, pure Java generation of **MFA Emergency Recovery Codes**:
  - Uses `SecureRandom` over an unambiguous 32-character alphabet (excludes `0/O`, `1/l`).
  - Generates human-friendly, formatted codes (e.g. `xxxxx-xxxxx`).
  - Provides normalization (`normalizeCode`) and formatting (`formatCode`) routines for user entry matching.

---

### 5. Spring Security & JWT Resource Server Suite
A modular security architecture for downstream services (`oauth2-resource-server`):

1. **`CommonJwtDecoderFactory`**: Fluent Lombok builders to configure `NimbusJwtDecoder`:
   - **`withJwkSetUri()`**: Remote JWKS discovery over HTTP with optional Spring Cache.
   - **`withJwkSource()`**: In-memory JWKS (used by authorization service) with dual-claim verifier disablement.
   - **`withValidators()`**: Attaches issuer validator and optional Redis blacklist validator with fail-fast `@NonNull` parameters.
2. **`CustomJwtAuthenticationConverter`**: Maps custom claims (`roles_permissions`) into Spring Security `GrantedAuthority` objects (`ROLE_*` and `PERM_*`), verifying active revocations on the fly. Configured via `@Builder`.
3. **`JwtBlacklistValidator`**: An `OAuth2TokenValidator<Jwt>` plugged into the decoder pipeline that rejects blacklisted JWT JTIs before request execution. Configured via `@Builder`.
4. **`TokenBlacklistService` / `RedisTokenBlacklistService`**: Redis-backed blacklist store with automatic TTL matching the token's remaining lifetime. Configured via `@Builder`.
5. **`PermissionRevocationService` / `RedisPermissionRevocationService`**: Near-instant permission revocation checks backed by local Caffeine caches and synced on startup via `ApplicationRunner` from Redis hashes. Configured via `@Builder`.
6. **`RoleRevocationService` / `RedisRoleRevocationService`**: Role-level revocation store with Caffeine caching, auto-sync on boot, and event listeners. Configured via `@Builder`.
7. **`CustomAuthenticationEntryPoint`**: Emits `401 Unauthorized` JSON responses using `ApiResponse.error(...)`, masking internal service errors. Configured via `@Builder`.
8. **`CustomAccessDeniedHandler`**: Emits `403 Forbidden` JSON responses using `ApiResponse.error(...)`. Configured via `@Builder`.

---

### 6. Redis Pub/Sub Utilities (`RedisPubSubHelper` & `SecurityTopics`)
Simplifies distributed event subscription for dynamic security invalidation across microservices:

```java
RedisPubSubHelper.builder()
        .container(container)
        .topicName(SecurityTopics.PERMISSION_REVOCATION)
        .onMessage(permissionRevocationService::handleRevocationEvent)
        .build();
```

- **`SecurityTopics`**: Centralized channel constants:
  - `SecurityTopics.SIGNING_KEY_REVOCATION` (`"auth:signing-key:revocation"`)
  - `SecurityTopics.PERMISSION_REVOCATION` (`"auth:permission:revocation"`)
  - `SecurityTopics.ROLE_REVOCATION` (`"auth:role:revocation"`)
- **`RedisPubSubHelper`**: Configured with `@Builder`, `@NonNull` containers/callbacks, and `Assert.hasText` topic validation. Returns `RedisMessageListenerContainer` for optional fluent chaining.

---

### 7. Security Utilities (`SecurityUtil` & `CommonSecurityExpressions`)
Located in `com.vaultix.common.security`. Provides static helper functions and security constants:
- `SecurityUtil.extractActorId(jwt)` &rarr; `UUID` (extracts and validates the subject UUID from `Jwt`, throwing `BadCredentialsException` if the token is null, missing, blank, or malformed).
- `CommonSecurityExpressions.IS_ADMIN` &rarr; `"hasRole('ADMIN')"` standard SpEL security expression for `@PreAuthorize` rules.

---

### 8. Cross-Service Notification Contracts (`NotificationEvent` & `NotificationChannel`)
Provides standard, immutable DTO records with Bean Validation for platform-wide event-driven messaging:
- **`NotificationChannel`**: Enum defining delivery mediums (`EMAIL`, `SMS`, `PUSH`, `IN_APP`).
- **`NotificationEvent`**: Record payload dispatched across RabbitMQ topic exchanges, carrying `eventId` (UUID), `templateCode` (e.g. `auth.password-reset`), `channel`, `recipient`, `recipientName`, `subject`, `params` map, and `createdAt` timestamp.

---

### 8. PII Masking Utilities (`MaskUtil`)
Centralized string masking for personally identifiable information (PII) before emitting log statements, previews, or challenges:
- **`MaskUtil.maskEmail(email)`**: Converts `vimal@gmail.com` to `v***l@gmail.com`. Safely handles short local parts (`a@example.com` &rarr; `a***@example.com`, `ab@example.com` &rarr; `a***b@example.com`).
- **`MaskUtil.maskPhone(phone)`**: Retains only the last 4 digits (e.g. `******7890`).
- **`MaskUtil.maskUsername(username)`**: Masks usernames (e.g. `vimalkumar` &rarr; `v***r`), automatically delegating to `maskEmail` if an `@` character is detected.

---

## Directory Structure

```
common/
├── pom.xml
├── README.md
└── src/main/java/com/vaultix/common/
    ├── constant/
    │   ├── CommonHeaders.java
    │   └── SecurityTopics.java
    ├── crypto/
    │   ├── AesGcmCryptoUtil.java
    │   ├── RecoveryCodeUtil.java
    │   └── TotpUtil.java
    ├── dto/
    │   ├── ApiResponse.java
    │   └── notification/
    │       ├── NotificationChannel.java
    │       └── NotificationEvent.java
    ├── exception/
    │   ├── BadRequestException.java
    │   ├── BaseGlobalExceptionHandler.java
    │   ├── ResourceConflictException.java
    │   └── ResourceNotFoundException.java
    ├── security/
    │   ├── CommonJwtDecoderFactory.java
    │   ├── CommonSecurityExpressions.java
    │   ├── CustomAccessDeniedHandler.java
    │   ├── CustomAuthenticationEntryPoint.java
    │   ├── CustomJwtAuthenticationConverter.java
    │   ├── JwtBlacklistValidator.java
    │   ├── PermissionRevocationService.java
    │   ├── RedisPermissionRevocationService.java
    │   ├── RedisRoleRevocationService.java
    │   ├── RedisTokenBlacklistService.java
    │   ├── RoleRevocationService.java
    │   ├── SecurityUtil.java
    │   └── TokenBlacklistService.java
    └── util/
        ├── ClientContextUtil.java
        ├── MaskUtil.java
        └── RedisPubSubHelper.java
```

---

## Consuming in Microservices

Add the dependency to any Vaultix microservice (e.g. `authorization/pom.xml`, `gateway/pom.xml`, `demo/pom.xml`):

```xml
<dependency>
    <groupId>com.vaultix</groupId>
    <artifactId>common</artifactId>
    <version>0.0.1</version>
</dependency>
```

---

## Local Build & Installation

Whenever changes are made to `common`, compile and install the updated JAR into your local Maven repository (`~/.m2/repository`):

### PowerShell / Windows:
```powershell
.\mvnw.cmd clean install
```

### Linux / macOS:
```bash
./mvnw clean install
```
