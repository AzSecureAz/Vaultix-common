package com.vaultix.common.security;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import lombok.AllArgsConstructor;
import lombok.Builder;

@Builder
@AllArgsConstructor
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final RoleRevocationService roleRevocationService;
    private final PermissionRevocationService permissionRevocationService;

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        UUID actorId = SecurityUtil.extractActorId(jwt);
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        return new JwtAuthenticationToken(jwt, authorities, actorId.toString());
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
