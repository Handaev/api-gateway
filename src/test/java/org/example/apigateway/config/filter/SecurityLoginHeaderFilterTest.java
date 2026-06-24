package org.example.apigateway.config.filter;

import org.example.apigateway.Utils.UtilsSecurity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

class SecurityLoginHeaderFilterTest {

    private SecurityLoginHeaderFilter filter;

    @BeforeEach
    void setUp() {
        this.filter = new SecurityLoginHeaderFilter();
    }

    @Test
    void userAuthenticated_shouldAddXUserLoginHeader() {
        AtomicReference<String> capturedHeader = new AtomicReference<>();

        WebTestClient webTestClient = WebTestClient.bindToWebHandler(exchange -> {
                    capturedHeader.set(exchange.getRequest().getHeaders().getFirst(UtilsSecurity.X_USER_LOGIN_HEADER));
                    return Mono.empty();
                })
                .webFilter(filter)
                .apply(springSecurity())
                .build();

        webTestClient.mutateWith(mockJwt()
                        .jwt(jwt -> jwt.subject("test-wrestler"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get()
                .exchange()
                .expectStatus().isOk();

        assertEquals("test-wrestler", capturedHeader.get());
    }

}
