package com.vaultix.common.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import tools.jackson.databind.ObjectMapper;

@AutoConfiguration
@ConditionalOnClass(JwtDecoder.class)
@AutoConfigureAfter(TokenBlacklistAutoConfiguration.class)
public class ResourceServerSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CustomJwtAuthenticationConverter customJwtAuthenticationConverter() {
        return new CustomJwtAuthenticationConverter();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "jakarta.servlet.http.HttpServletRequest")
    public CustomAuthenticationEntryPoint customAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new CustomAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "jakarta.servlet.http.HttpServletRequest")
    public CustomAccessDeniedHandler customAccessDeniedHandler(ObjectMapper objectMapper) {
        return new CustomAccessDeniedHandler(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtBlacklistValidator jwtBlacklistValidator(TokenBlacklistService tokenBlacklistService) {
        return new JwtBlacklistValidator(tokenBlacklistService);
    }

    @Bean
    @ConditionalOnProperty(name = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
    @ConditionalOnMissingBean(JwtDecoder.class)
    public JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri,
            @Value("${vaultix.security.jwt.issuer:https://auth.vaultix.com}") String expectedIssuer,
            JwtBlacklistValidator jwtBlacklistValidator) {

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        OAuth2TokenValidator<Jwt> defaultValidator = JwtValidators.createDefaultWithIssuer(expectedIssuer);
        OAuth2TokenValidator<Jwt> combinedValidator = new DelegatingOAuth2TokenValidator<>(defaultValidator, jwtBlacklistValidator);

        jwtDecoder.setJwtValidator(combinedValidator);
        return jwtDecoder;
    }
}
