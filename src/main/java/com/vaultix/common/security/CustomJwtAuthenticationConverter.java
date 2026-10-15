package com.vaultix.common.security;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        Object rolesPermsObj = jwt.getClaims().get("roles_permissions");
        if (rolesPermsObj instanceof Map<?, ?> rolePermsMap) {
            for (Map.Entry<?, ?> entry : rolePermsMap.entrySet()) {
                if (entry.getKey() != null) {
                    authorities.add(new SimpleGrantedAuthority(entry.getKey().toString()));
                }
                if (entry.getValue() instanceof Collection<?> perms) {
                    for (Object perm : perms) {
                        if (perm != null) {
                            authorities.add(new SimpleGrantedAuthority(perm.toString()));
                        }
                    }
                }
            }
        }

        return Set.copyOf(authorities);
    }
}
