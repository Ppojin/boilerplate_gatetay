package com.ppojin.gateway.security;


import com.ppojin.gateway.webflux.TokenDTO;
import com.ppojin.gateway.webflux.TokenService;
import feign.FeignException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.StaticResourceLocation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.SecurityWebFilterChain;

import org.springframework.security.web.server.util.matcher.*;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

@Slf4j
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
public class SecurityConfiguration {

    private final Converter<Jwt, Mono<KeycloakAuthenticationToken>> authorizationConverter;
    private final TokenService tokenService;

    public SecurityConfiguration(
            Converter<Jwt, Mono<KeycloakAuthenticationToken>> keycloakAuthorizationConverter,
            TokenService tokenService
    ) {
        this.authorizationConverter = keycloakAuthorizationConverter;
        this.tokenService = tokenService;
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        var keycloakMatcher = pathMatchers("/realms/**", "/resources/**", "/robots.txt");
        var indexMatcher = pathMatchers("/_next/**", "/__nextjs_original-stack-frame");
        var staticMatcher = pathMatchers(
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
            ServerHttpRequest req = exchange.getRequest();
            log.info("security start : {}", req.getURI());
            return chain.filter(exchange);
        }, SecurityWebFiltersOrder.FIRST);

        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable);

        http.oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                .jwt(jwtSpec -> jwtSpec
                        .jwtAuthenticationConverter(authorizationConverter)
                )
        );

        http.authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
                .pathMatchers("/test/**", "/", "/logout")  // TODO: 500 에러 왜 날까 (http://app.ppojin.localhost:30080/test?session_state=710bbd38-fa14-48c2-a54c-78d6c0bbc70c&code=c5c447b8-4460-48f5-887f-5741fe349f3e.710bbd38-fa14-48c2-a54c-78d6c0bbc70c.5ad473f7-f2e8-46cf-a213-5e4710a89371)
                .permitAll()
                .pathMatchers("/token/**", "/token", "/refresh")
                .permitAll()
                .pathMatchers("/httpbin/**")
                .authenticated()
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
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    DataBufferFactory bufferFactory = response.bufferFactory();
                    return Mono.empty();
//                    response.setStatusCode(HttpStatus.NOT_FOUND);
//                    DataBufferFactory bufferFactory = response.bufferFactory();
//                    return response.writeWith(
//                            Mono.just(bufferFactory.wrap("404 error!".getBytes(StandardCharsets.UTF_8)))
//                    );
                })
        );

        http.addFilterBefore((ServerWebExchange exchange, WebFilterChain chain) -> {
            log.info("security confirmed : {}", exchange.getRequest().getURI());
            return chain.filter(exchange);
        }, SecurityWebFiltersOrder.LAST);

        return http.build();
    }
}
