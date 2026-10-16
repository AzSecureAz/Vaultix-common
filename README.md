# Vaultix Common Library

The shared core library for the **Vaultix** microservices platform, providing cross-cutting concerns, client context utilities, unified API envelopes, cryptographic helpers, and Spring Security resource server components.

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

## Core Modules & Capabilities

### 1. Unified API Response (`ApiResponse<T>`)
A standardized JSON envelope returned across all microservices:
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": { ... },
  "timestamp": "2026-10-16T12:00:00Z",
  "errors": null
}
```
- **Factory Helpers**:
  - `ApiResponse.success(data)` / `ApiResponse.success(message, data)`
  - `ApiResponse.error(message)` / `ApiResponse.error(message, errorsList)`

### 2. Client Context Resolution (`ClientContextUtil`)
Extracts and sanitizes headers injected downstream by the API Gateway:
- **`X-Client-IP`**: Client's public IP address.
- **`X-Device-Info`**: Browser and operating system summary.
- **`X-Device-Location`**: Resolved geographic location (e.g., `City, Country`).
- **`ClientContextUtil.extract(HttpServletRequest)`**: Returns a strongly typed `ClientContext(String ip, String deviceInfo, String location)` record, guaranteeing non-null, non-blank values (defaults to `"Unknown"`).

### 3. Header Constants (`CommonHeaders`)
Type-safe HTTP header constants:
- `X_CLIENT_IP = "X-Client-IP"`
- `X_DEVICE_INFO = "X-Device-Info"`
- `X_DEVICE_LOCATION = "X-Device-Location"`
- `AUTHORIZATION = "Authorization"`
- `BEARER_PREFIX = "Bearer "`

### 4. Cryptographic Utilities (`AesGcmCryptoUtil`)
Authenticated encryption using standard **AES-256 GCM**:
- Secure 12-byte IV generation per encryption operation.
- Constant-time MAC authentication verification against tampering.
- Base64-encoded URL-safe payloads.

### 5. Spring Security & JWT Resource Server Suite
Components for securing downstream resource services (`oauth2-resource-server`):
- **`CustomJwtAuthenticationConverter`**: Maps custom JWT claims (`roles` and `permissions`) into Spring Security `GrantedAuthority` objects (`ROLE_*` and `PERM_*`).
- **`TokenBlacklistService` / `RedisTokenBlacklistService`**: Redis-backed blacklist store with automatic TTL expiration matching the JWT's remaining lifetime.
- **`JwtBlacklistValidator`**: `OAuth2TokenValidator<Jwt>` plugged into the JWT decoder pipeline to reject revoked token JTIs before processing requests.
- **`CustomAuthenticationEntryPoint`**: Emits consistent JSON 401 Unauthorized responses using `ApiResponse.error(...)`.
- **`CustomAccessDeniedHandler`**: Emits consistent JSON 403 Forbidden responses using `ApiResponse.error(...)`.

---

## Directory Structure

```
common/
├── pom.xml
├── README.md
└── src/main/java/com/vaultix/common/
    ├── constant/
    │   └── CommonHeaders.java
    ├── crypto/
    │   └── AesGcmCryptoUtil.java
    ├── dto/
    │   └── ApiResponse.java
    ├── security/
    │   ├── CommonSecurityExpressions.java
    │   ├── CustomAccessDeniedHandler.java
    │   ├── CustomAuthenticationEntryPoint.java
    │   ├── CustomJwtAuthenticationConverter.java
    │   ├── JwtBlacklistValidator.java
    │   ├── RedisTokenBlacklistService.java
    │   └── TokenBlacklistService.java
    └── util/
        └── ClientContextUtil.java
```

---

## Consuming in Microservices

Add the dependency to any Vaultix microservice (e.g. `authorization/pom.xml`, `gateway/pom.xml`):

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

