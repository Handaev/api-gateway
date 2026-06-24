package org.example.apigateway.config;

import org.example.apigateway.Utils.UtilsSecurity;
import org.example.apigateway.config.filter.SecurityLoginHeaderFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, KeycloakReactiveAuthorizationConverter keycloakConverter) {
        http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(UtilsSecurity.ACCESSED_PATH).hasAnyRole(UtilsSecurity.ROLE_USER, UtilsSecurity.ROLE_ADMIN)
                        .anyExchange().authenticated()
                )
                .addFilterAfter(new SecurityLoginHeaderFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(keycloakConverter))
                );

        return http.build();
    }

    @Bean
    public JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter() {
        return new JwtGrantedAuthoritiesConverter();
    }

    @Bean
    public KeycloakReactiveAuthorizationConverter keycloakReactiveAuthorizationConverter(
            JwtGrantedAuthoritiesConverter defaultAuthoritiesConverter) {
        return new KeycloakReactiveAuthorizationConverter(defaultAuthoritiesConverter);
    }
}