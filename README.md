# Vaultix Common Library

The shared core library for the **Vaultix** microservices platform.

This module provides common utilities, cross-cutting concerns, shared DTOs, and base exception classes across all Vaultix microservices.

---

## Artifact Details

- **Group ID**: `com.vaultix`
- **Artifact ID**: `common`
- **Current Version**: `0.0.1`
- **Packaging**: Standard reusable library JAR (`jar`)

---

## Intended Responsibilities

This shared library is designed to contain:
- **Common DTOs & Models**: Shared request/response payloads, pagination models, API wrappers (`ApiResponse<T>`).
- **Exceptions & Error Handling**: Base domain exceptions, error codes, and global error response templates.
- **Security Utilities**: Common JWT helpers, role/permission constants, and token validation utilities.
- **Utility Classes**: String/Date helpers, JSON serialization helpers, and validation utilities.

---

## How to Consume in Microservices

Add the dependency to your microservice's `pom.xml` (e.g. in `authorization/pom.xml`):

```xml
<dependency>
    <groupId>com.vaultix</groupId>
    <artifactId>common</artifactId>
    <version>0.0.1</version>
</dependency>
```

---

## Local Build & Installation

To build and publish updates to your local Maven repository (`~/.m2/repository`):

### Linux / macOS:
```bash
./mvnw clean install
```

### Windows (PowerShell / Command Prompt):
```powershell
.\mvnw.cmd clean install
```
