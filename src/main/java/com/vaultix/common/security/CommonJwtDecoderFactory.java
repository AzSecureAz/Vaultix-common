package com.vaultix.common.security;

import org.springframework.cache.Cache;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import lombok.Builder;

public final class CommonJwtDecoderFactory {

    private CommonJwtDecoderFactory() {
    }

    /**
     * Builds a NimbusJwtDecoder fetching remote JWKS over HTTP with an optional
     * cache.
     *
     * @param jwkSetUri the remote JWK Set URI
     * @param cache optional Spring Cache for holding JWKS; pass null for
     * default Nimbus caching
     * @param expectedIssuer the expected issuer claim ("iss")
     * @param blacklistValidator optional Redis JWT blacklist validator
     * @return the configured JwtDecoder
     */
    @Builder(builderMethodName = "withJwkSetUri", builderClassName = "JwkSetUriDecoderBuilder", buildMethodName = "build")
    public static JwtDecoder create(
            String jwkSetUri,
            Cache cache,
            String expectedIssuer,
            JwtBlacklistValidator blacklistValidator) {

        Assert.hasText(jwkSetUri, "jwkSetUri must not be null or blank");

        NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder builder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri);
        if (cache != null) {
            builder.cache(cache);
        }

        NimbusJwtDecoder decoder = builder.build();
        return withValidators()
                .decoder(decoder)
                .expectedIssuer(expectedIssuer)
                .blacklistValidator(blacklistValidator)
                .build();
    }

    /**
     * Builds a NimbusJwtDecoder backed by an in-memory JWKSource (e.g., in
     * authorization service). Disables duplicate claims verification in
     * DefaultJWTProcessor so Spring Security's OAuth2TokenValidator pipeline
     * has single-point control.
     *
     * @param jwkSource the in-memory JWK source
     * @param expectedIssuer the expected issuer claim ("iss")
     * @param blacklistValidator optional Redis JWT blacklist validator
     * @return the configured JwtDecoder
     */
    @Builder(builderMethodName = "withJwkSource", builderClassName = "JwkSourceDecoderBuilder", buildMethodName = "build")
    public static JwtDecoder create(
            JWKSource<SecurityContext> jwkSource,
            String expectedIssuer,
            JwtBlacklistValidator blacklistValidator) {

        Assert.notNull(jwkSource, "jwkSource must not be null");

        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
        });

        NimbusJwtDecoder decoder = new NimbusJwtDecoder(jwtProcessor);
        return withValidators()
                .decoder(decoder)
                .expectedIssuer(expectedIssuer)
                .blacklistValidator(blacklistValidator)
                .build();
    }

    /**
     * Configures the standard Vaultix JWT token validators (issuer and optional
     * Redis blacklist) on a NimbusJwtDecoder.
     *
     * @param decoder the NimbusJwtDecoder to configure
     * @param expectedIssuer the expected issuer claim ("iss")
     * @param blacklistValidator optional Redis JWT blacklist validator
     * @return the configured NimbusJwtDecoder
     */
    @Builder(builderMethodName = "withValidators", builderClassName = "ValidatorBuilder", buildMethodName = "build")
    public static NimbusJwtDecoder configureValidators(
            NimbusJwtDecoder decoder,
            String expectedIssuer,
            JwtBlacklistValidator blacklistValidator) {

        Assert.notNull(decoder, "decoder must not be null");

        OAuth2TokenValidator<Jwt> defaultValidator = expectedIssuer != null && !expectedIssuer.isBlank()
                ? JwtValidators.createDefaultWithIssuer(expectedIssuer)
                : JwtValidators.createDefault();

        OAuth2TokenValidator<Jwt> delegatingValidator = (blacklistValidator != null)
                ? new DelegatingOAuth2TokenValidator<>(defaultValidator, blacklistValidator)
                : defaultValidator;

        decoder.setJwtValidator(delegatingValidator);
        return decoder;
    }
}
