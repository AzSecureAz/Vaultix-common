package com.vaultix.common.exception;

import java.lang.reflect.Field;
import java.lang.reflect.RecordComponent;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.MessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.validation.method.ParameterValidationResult;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.vaultix.common.dto.ApiResponse;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class BaseGlobalExceptionHandler {

    private static final Map<String, String> FIELD_NAME_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, String> SNAKE_CASE_CACHE = new ConcurrentHashMap<>();

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new LinkedHashMap<>();
        Object target = ex.getBindingResult().getTarget();

        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            String fieldKey = resolveJsonFieldName(target, fieldError.getField());
            errors.putIfAbsent(fieldKey, fieldError.getDefaultMessage());
        }
        for (ObjectError globalError : ex.getBindingResult().getGlobalErrors()) {
            errors.putIfAbsent(toSnakeCase(globalError.getObjectName()), globalError.getDefaultMessage());
        }
        log.warn("Validation failed for request: {}", errors);
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Validation failed", errors));
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<ApiResponse<Void>> handleHandlerMethodValidationException(HandlerMethodValidationException ex) {
        Map<String, String> errors = new LinkedHashMap<>();
        for (ParameterValidationResult result : ex.getParameterValidationResults()) {
            if (result == null) {
                continue;
            }
            String paramName = result.getMethodParameter() != null ? result.getMethodParameter().getParameterName() : null;
            if (result.getResolvableErrors() == null) {
                continue;
            }
            for (MessageSourceResolvable error : result.getResolvableErrors()) {
                if (error == null) {
                    continue;
                }
                String fieldKey;
                if (error instanceof FieldError fe) {
                    fieldKey = resolveJsonFieldName(result.getArgument(), fe.getField());
                } else {
                    fieldKey = paramName != null ? toSnakeCase(paramName) : "parameter";
                }
                String defaultMessage = error.getDefaultMessage();
                errors.putIfAbsent(fieldKey, defaultMessage != null && !defaultMessage.isBlank() ? defaultMessage : "Invalid value");
            }
        }
        log.warn("Method parameter validation failed: {}", errors);
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Validation failed", errors));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<Void>> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex) {
        log.warn("HTTP method not supported: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(ApiResponse.error(ex.getMessage()));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Void>> handleConstraintViolationException(ConstraintViolationException ex) {
        Map<String, String> errors = new LinkedHashMap<>();
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            String propertyPath = violation.getPropertyPath().toString();
            String fieldName = propertyPath.contains(".")
                    ? propertyPath.substring(propertyPath.lastIndexOf('.') + 1)
                    : propertyPath;
            errors.putIfAbsent(toSnakeCase(fieldName), violation.getMessage());
        }
        log.warn("Constraint violation: {}", errors);
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Validation failed", errors));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResponse<Void>> handleMethodArgumentTypeMismatchException(MethodArgumentTypeMismatchException ex) {
        String paramName = toSnakeCase(ex.getName());
        String expectedType = ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "valid type";
        String errorMessage = String.format("Parameter '%s' should be of type %s", paramName, expectedType);
        log.warn("Method argument type mismatch: {}", errorMessage);
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Invalid parameter type", Map.of(paramName, errorMessage)));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        log.warn("Malformed HTTP request body: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error("Malformed JSON request body"));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<Void>> handleAuthenticationException(AuthenticationException ex) {
        log.warn("Authentication failed: {}", ex.getMessage());

        if (ex instanceof InternalAuthenticationServiceException) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Authentication failed"));
        }

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.error(ex.getMessage() != null && !ex.getMessage().isBlank()
                        ? ex.getMessage()
                        : "Authentication failed"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDeniedException(AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.error("Access denied: You do not have permission to access this resource"));
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiResponse<Void>> handleBadRequestException(BadRequestException ex) {
        log.warn("Bad request: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(ex.getMessage() != null && !ex.getMessage().isBlank()
                        ? ex.getMessage()
                        : "Bad request"));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.warn("Resource not found: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error(ex.getMessage() != null && !ex.getMessage().isBlank()
                        ? ex.getMessage()
                        : "Resource not found"));
    }

    @ExceptionHandler(ResourceConflictException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceConflictException(ResourceConflictException ex) {
        log.warn("Resource conflict: {}", ex.getMessage());
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ApiResponse.error(ex.getMessage() != null && !ex.getMessage().isBlank()
                        ? ex.getMessage()
                        : "Resource conflict"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericException(Exception ex) {
        log.error("Unhandled internal server error occurred: {}", ex.getMessage(), ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("An internal server error occurred. Please try again later."));
    }

    protected String resolveJsonFieldName(Object target, String fieldName) {
        if (fieldName == null || fieldName.isBlank()) {
            return "field";
        }
        if (target == null) {
            return toSnakeCase(fieldName);
        }

        String cacheKey = target.getClass().getName() + "#" + fieldName;
        return FIELD_NAME_CACHE.computeIfAbsent(cacheKey, k -> {
            Class<?> clazz = target.getClass();

            if (clazz.isRecord()) {
                for (RecordComponent rc : clazz.getRecordComponents()) {
                    if (rc.getName().equals(fieldName)) {
                        JsonProperty jsonProp = rc.getAnnotation(JsonProperty.class);
                        if (jsonProp != null && !jsonProp.value().isBlank()) {
                            return jsonProp.value();
                        }
                    }
                }
            }

            Class<?> current = clazz;
            while (current != null && current != Object.class) {
                try {
                    Field declaredField = current.getDeclaredField(fieldName);
                    JsonProperty jsonProp = declaredField.getAnnotation(JsonProperty.class);
                    if (jsonProp != null && !jsonProp.value().isBlank()) {
                        return jsonProp.value();
                    }
                    break;
                } catch (NoSuchFieldException ignored) {
                    current = current.getSuperclass();
                }
            }

            return toSnakeCase(fieldName);
        });
    }

    protected static String toSnakeCase(String input) {
        if (input == null || input.isBlank()) {
            return input;
        }
        return SNAKE_CASE_CACHE.computeIfAbsent(input, BaseGlobalExceptionHandler::computeSnakeCase);
    }

    private static String computeSnakeCase(String input) {
        StringBuilder result = new StringBuilder(input.length() + 5);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (Character.isUpperCase(c)) {
                if (i > 0 && input.charAt(i - 1) != '_' && input.charAt(i - 1) != '.' && input.charAt(i - 1) != '-') {
                    result.append('_');
                }
                result.append(Character.toLowerCase(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }
}
