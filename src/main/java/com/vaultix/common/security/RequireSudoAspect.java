package com.vaultix.common.security;

import java.lang.reflect.Method;
import java.util.UUID;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.vaultix.common.exception.SudoRequiredException;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Aspect
@Builder
@AllArgsConstructor
public class RequireSudoAspect {

    @NonNull
    private final SudoService sudoService;

    @Around("@annotation(com.vaultix.common.security.RequireSudo) || @within(com.vaultix.common.security.RequireSudo)")
    public Object enforceSudo(ProceedingJoinPoint joinPoint) throws Throwable {
        RequireSudo requireSudo = resolveRequireSudo(joinPoint);
        if (requireSudo == null) {
            return joinPoint.proceed();
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BadCredentialsException("Unauthenticated request");
        }

        Jwt jwt = extractJwt(authentication);
        UUID sessionId = SecurityUtil.extractSessionId(jwt);

        long maxAgeSeconds = requireSudo.maxAgeSeconds();
        boolean sudoActive = sudoService.isSudoActive(sessionId, maxAgeSeconds);

        if (!sudoActive) {
            log.warn("Sudo check failed for session ID: {} on method: {}",
                    sessionId, joinPoint.getSignature().toShortString());
            throw new SudoRequiredException();
        }

        return joinPoint.proceed();
    }

    private RequireSudo resolveRequireSudo(ProceedingJoinPoint joinPoint) {
        if (joinPoint.getSignature() instanceof MethodSignature methodSignature) {
            Method method = methodSignature.getMethod();
            RequireSudo methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(method, RequireSudo.class);
            if (methodAnnotation != null) {
                return methodAnnotation;
            }
        }

        Class<?> targetClass = joinPoint.getTarget() != null ? joinPoint.getTarget().getClass() : null;
        if (targetClass != null) {
            return AnnotatedElementUtils.findMergedAnnotation(targetClass, RequireSudo.class);
        }

        return null;
    }

    private Jwt extractJwt(Authentication authentication) {
        if (authentication.getPrincipal() instanceof Jwt principalJwt) {
            return principalJwt;
        }
        if (authentication instanceof JwtAuthenticationToken jwtAuthToken) {
            return jwtAuthToken.getToken();
        }
        throw new BadCredentialsException("Authentication principal is not a valid JWT token");
    }
}
