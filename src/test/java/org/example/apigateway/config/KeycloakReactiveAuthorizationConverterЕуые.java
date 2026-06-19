package org.example.apigateway.config;

import org.example.apigateway.Utils.UtilsSecurity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakReactiveAuthorizationConverterTest {

    @Mock
    private JwtGrantedAuthoritiesConverter defaultAuthoritiesConverter;

    @InjectMocks
    private KeycloakReactiveAuthorizationConverter converter;

    @Test
    void shouldKeycloakRolesSuccessfully() {
        Map<String, Object> realmAccess = Map.of(
                UtilsSecurity.NAME_ATTRIBUTE_ROLES, List.of("ROLE_ADMIN")
        );

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "non")
                .subject("123")
                .claim(UtilsSecurity.PREFERRED_USERNAME, "zhora")
                .claim(UtilsSecurity.REALM_ACCESS, realmAccess)
                .build();

        List<GrantedAuthority> defaultAuthorities = List.of(new SimpleGrantedAuthority("SCOPE_openid"));
        when(defaultAuthoritiesConverter.convert(jwt)).thenReturn(defaultAuthorities);

        Mono<AbstractAuthenticationToken> resultMono = converter.convert(jwt);

        StepVerifier.create(resultMono)
                .assertNext(authToken -> {
                    assertThat(authToken.getName()).isEqualTo("zhora");

                    Set<String> authorities = authToken.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toSet());

                    assertThat(authorities).containsExactlyInAnyOrder("SCOPE_openid", "ROLE_ADMIN");
                })
                .verifyComplete();
    }

    @Test
    void shouldFallbackUsernameIsMissing() {
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "non")
                .subject("error")
                .claim(UtilsSecurity.REALM_ACCESS, Collections.emptyMap())
                .build();

        when(defaultAuthoritiesConverter.convert(jwt)).thenReturn(Collections.emptyList());

        Mono<AbstractAuthenticationToken> resultMono = converter.convert(jwt);

        StepVerifier.create(resultMono)
                .assertNext(authToken -> {
                    assertThat(authToken.getName()).isEqualTo("error");
                })
                .verifyComplete();
    }
}