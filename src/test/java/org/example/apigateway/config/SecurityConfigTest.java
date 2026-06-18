package org.example.apigateway.config;

import org.example.apigateway.Utils.UtilsSecurity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.*;

@WebFluxTest
@Import(SecurityConfig.class)
class SecurityConfigTest {

    @Autowired
    private ApplicationContext context;

    private WebTestClient webTestClient;

    private static final String PROTECTED_PATH = "/flow-manager/files/7/status";

    @BeforeEach
    void setUp() {
        this.webTestClient = WebTestClient
                .bindToApplicationContext(context)
                .apply(springSecurity())
                .configureClient()
                .build();
    }

    @Test
    void noToken_401Unauthorized() {
        webTestClient.get()
                .uri(PROTECTED_PATH)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void requiredRole_NotFound() {
        webTestClient.mutateWith(mockJwt()
                        .authorities(new SimpleGrantedAuthority("ROLE_" + UtilsSecurity.ROLE_USER)))
                .get()
                .uri(PROTECTED_PATH)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void invalidRole_403() {
        webTestClient.mutateWith(mockJwt()
                        .authorities(new SimpleGrantedAuthority("ROLE_RANDOM_USER")))
                .get()
                .uri(PROTECTED_PATH)
                .exchange()
                .expectStatus().isForbidden();
    }
}