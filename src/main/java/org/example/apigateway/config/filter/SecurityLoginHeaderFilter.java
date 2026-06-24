package org.example.apigateway.config.filter;

import org.example.apigateway.Utils.UtilsSecurity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class SecurityLoginHeaderFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(authentication -> {
                    String username = authentication.getAuthentication().getName();

                    return exchange.mutate()
                            .request(requestBuilder -> requestBuilder.header(UtilsSecurity.X_USER_LOGIN_HEADER, username))
                            .build();
                })
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);

    }
}