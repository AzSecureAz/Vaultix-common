package com.vaultix.common.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Indicates that the annotated controller endpoint or class requires an
 * elevated Sudo session. The user must have verified credentials (password,
 * passkey, or MFA) within the active Sudo duration for the current session.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequireSudo {

    /**
     * Custom maximum age in seconds for the Sudo elevation. When set to 0
     * (default), the global Sudo duration configured in application properties
     * is used.
     */
    long maxAgeSeconds() default 0;
}
