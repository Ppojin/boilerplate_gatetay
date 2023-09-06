package com.ppojin.gateway.security;


import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.StaticResourceLocation;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.web.server.SecurityWebFilterChain;

import org.springframework.security.web.server.util.matcher.*;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

@Slf4j
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
public class SecurityConfiguration {

    private final Converter<Jwt, Mono<KeycloakAuthenticationToken>> authenticationConverter;

    public SecurityConfiguration(Converter<Jwt, Mono<KeycloakAuthenticationToken>> keycloakAuthenticationConverter) {
        this.authenticationConverter = keycloakAuthenticationConverter;
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        var keycloakMatcher = ServerWebExchangeMatchers.pathMatchers("/realms/**", "/resources/**", "/robots.txt");
        var indexMatcher = ServerWebExchangeMatchers.pathMatchers("/", "/index.html");
        var staticMatcher = ServerWebExchangeMatchers.pathMatchers(
                EnumSet.allOf(StaticResourceLocation.class).stream()
                        .flatMap(StaticResourceLocation::getPatterns)
                        .toArray(String[]::new)
        );
        http.securityMatcher(
                new NegatedServerWebExchangeMatcher(
                        new OrServerWebExchangeMatcher(
                                staticMatcher,
                                keycloakMatcher,
                                indexMatcher
                        )
                )
        );

        http.addFilterAfter((ServerWebExchange exchange, WebFilterChain chain) -> {
            log.info("security start");
            return chain.filter(exchange);
        }, SecurityWebFiltersOrder.FIRST);

        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable);

        http.oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                .jwt(jwtSpec -> jwtSpec
//                        .jwtDecoder()
                        .jwtAuthenticationConverter(authenticationConverter)
                )
        );

        http.authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
//                .pathMatchers("/realms/**", "/resources/**", "/robots.txt")
//                .permitAll()
                .anyExchange()
                .hasAnyAuthority("admin", "user")
        );

        http.exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec
                .accessDeniedHandler((ServerWebExchange exchange, AccessDeniedException e) -> {
                    log.info("[권한 불충분]");
                    return exchange.getResponse().writeWith(Mono.empty());
                })
                .authenticationEntryPoint((ServerWebExchange exchange, AuthenticationException e) -> {
                    log.info("[인증되지 않음] {}", exchange.getRequest().getPath());
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.NOT_FOUND);
                    DataBufferFactory bufferFactory = response.bufferFactory();
                    return response.writeWith(
                            Mono.just(bufferFactory.wrap("404 error!".getBytes(StandardCharsets.UTF_8)))
                    );
                })
        );

        http.addFilterBefore((ServerWebExchange exchange, WebFilterChain chain) -> {
            log.info("security confirm");
            return chain.filter(exchange);
        }, SecurityWebFiltersOrder.LAST);

        return http.build();
    }
}
