package org.example.apigateway.config;

import lombok.RequiredArgsConstructor;
import org.example.apigateway.Utils.UtilsSecurity;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class KeycloakReactiveAuthorizationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private final JwtGrantedAuthoritiesConverter defaultAuthoritiesConverter;

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        Collection<GrantedAuthority> defaultAuthorities = defaultAuthoritiesConverter.convert(jwt);

        Collection<GrantedAuthority> keycloakRoles = extractRoles(jwt);

        return Flux.fromIterable(defaultAuthorities)
                .concatWith(Flux.fromIterable(keycloakRoles))
                .collect(Collectors.toSet())
                .map(authorities -> {
                    String principalClaimName = jwt.getClaimAsString(UtilsSecurity.PREFERRED_USERNAME);
                    if (Objects.isNull(principalClaimName)) {
                        principalClaimName = jwt.getSubject();
                    }
                    return new JwtAuthenticationToken(jwt, authorities, principalClaimName);
                });
    }

    private Collection<GrantedAuthority> extractRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim(UtilsSecurity.REALM_ACCESS);

        if (Objects.isNull(realmAccess) || !realmAccess.containsKey(UtilsSecurity.NAME_ATTRIBUTE_ROLES)) {
            return Collections.emptyList();
        }

        Collection<String> roles = (Collection<String>) realmAccess.get(UtilsSecurity.NAME_ATTRIBUTE_ROLES);
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.startsWith(UtilsSecurity.PREFIX_ROLE) ? role : UtilsSecurity.PREFIX_ROLE + role))
                .collect(Collectors.toList());
    }
}