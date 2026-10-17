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
        configureValidators(decoder, expectedIssuer, blacklistValidator);
        return decoder;
    }

    /**
     * Convenience method to build a NimbusJwtDecoder fetching remote JWKS over
     * HTTP using the default built-in cache.
     */
    public static JwtDecoder create(
            String jwkSetUri,
            String expectedIssuer,
            JwtBlacklistValidator blacklistValidator) {
        return create(jwkSetUri, null, expectedIssuer, blacklistValidator);
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
        configureValidators(decoder, expectedIssuer, blacklistValidator);
        return decoder;
    }

    private static void configureValidators(
            NimbusJwtDecoder decoder,
            String expectedIssuer,
            JwtBlacklistValidator blacklistValidator) {

        OAuth2TokenValidator<Jwt> defaultValidator = expectedIssuer != null && !expectedIssuer.isBlank()
                ? JwtValidators.createDefaultWithIssuer(expectedIssuer)
                : JwtValidators.createDefault();

        OAuth2TokenValidator<Jwt> delegatingValidator = (blacklistValidator != null)
                ? new DelegatingOAuth2TokenValidator<>(defaultValidator, blacklistValidator)
                : defaultValidator;

        decoder.setJwtValidator(delegatingValidator);
    }
}
