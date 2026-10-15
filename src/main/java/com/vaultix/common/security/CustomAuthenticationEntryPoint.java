package com.vaultix.common.security;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.vaultix.common.dto.ApiResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.ObjectMapper;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {

        String description = "Authentication required";
        if (authException instanceof OAuth2AuthenticationException oauth2Ex && oauth2Ex.getError() != null && oauth2Ex.getError().getDescription() != null) {
            description = oauth2Ex.getError().getDescription();
        } else if (authException != null && authException.getMessage() != null && !authException.getMessage().isBlank()) {
            description = authException.getMessage();
        }

        log.warn("Unauthorized access attempt to [{}]: {}", request.getRequestURI(), description);

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"" + description + "\"");

        ApiResponse<Void> apiResponse = ApiResponse.error(description);
        objectMapper.writeValue(response.getOutputStream(), apiResponse);
    }
}
