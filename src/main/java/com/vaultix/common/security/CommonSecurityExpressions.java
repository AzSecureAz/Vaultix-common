package com.vaultix.common.security;

public final class CommonSecurityExpressions {

    private CommonSecurityExpressions() {
    }

    public static final String IS_ADMIN = "hasRole('ADMIN')";
}
