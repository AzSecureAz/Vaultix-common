package com.vaultix.common.security;

import java.time.Instant;
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

    private final RoleRevocationService roleRevocationService;
    private final PermissionRevocationService permissionRevocationService;

    public CustomJwtAuthenticationConverter() {
        this(null, null);
    }

    public CustomJwtAuthenticationConverter(RoleRevocationService roleRevocationService) {
        this(roleRevocationService, null);
    }

    public CustomJwtAuthenticationConverter(PermissionRevocationService permissionRevocationService) {
        this(null, permissionRevocationService);
    }

    public CustomJwtAuthenticationConverter(
            RoleRevocationService roleRevocationService,
            PermissionRevocationService permissionRevocationService) {
        this.roleRevocationService = roleRevocationService;
        this.permissionRevocationService = permissionRevocationService;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        Instant issuedAt = jwt.getIssuedAt();

        Object rolesPermsObj = jwt.getClaims().get("roles_permissions");
        if (rolesPermsObj instanceof Map<?, ?> rolePermsMap) {
            for (Map.Entry<?, ?> entry : rolePermsMap.entrySet()) {
                if (entry.getKey() != null) {
                    String roleName = entry.getKey().toString();
                    if (roleRevocationService != null && roleRevocationService.isRevoked(roleName, issuedAt)) {
                        continue;
                    }
                    authorities.add(new SimpleGrantedAuthority(roleName));
                }
                if (entry.getValue() instanceof Collection<?> perms) {
                    for (Object perm : perms) {
                        if (perm != null) {
                            String permName = perm.toString();
                            if (permissionRevocationService != null && permissionRevocationService.isRevoked(permName, issuedAt)) {
                                continue;
                            }
                            authorities.add(new SimpleGrantedAuthority(permName));
                        }
                    }
                }
            }
        }

        return Set.copyOf(authorities);
    }
}
