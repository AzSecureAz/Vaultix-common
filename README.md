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

## Documentation Index

Detailed module guides, class contracts, and cryptographic specifications are maintained in the [`docs/`](docs/) directory:

| Document | Description |
| :--- | :--- |
| 📖 [**Modules & Capabilities Guide**](docs/MODULES.md) | In-depth breakdown of all 9 core library modules: Unified API responses (`ApiResponse<T>`), Centralized exception handling (`BaseGlobalExceptionHandler`), Client context resolution, Pure Java RFC 6238/4226 TOTP & AES-256 GCM crypto, Spring Security Resource Server suite, Redis Pub/Sub invalidation, Security expressions, Notification event contracts, and PII masking. |

---

## Directory Structure

```
common/
├── pom.xml
├── README.md
├── docs/
│   └── MODULES.md
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
