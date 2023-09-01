package com.ppojin.gateway.security;


import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.FutureMono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

@Slf4j
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
public class SecurityConfiguration {

    private static final String USERNAME_CLAIM = "preferred_username";

    private final Converter<Jwt, Collection<GrantedAuthority>> converter;
//    private final Converter<Jwt, Flux<GrantedAuthority>> jwtGrantedAuthoritiesConverter;

    public SecurityConfiguration(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
        this.converter = jwtGrantedAuthoritiesConverter;
//        this.jwtGrantedAuthoritiesConverter = new ReactiveJwtGrantedAuthoritiesConverterAdapter(
//                this.converter
//        );
    }

    private Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        return Mono.just(new JwtAuthenticationToken(jwt, converter.convert(jwt), extractUsername(jwt)));
//        return Objects.requireNonNull(
//                        this.jwtGrantedAuthoritiesConverter.convert(jwt),
//                        "jwtGrantedAuthoritiesConverter cannot be null"
//                )
//                .collectList()
//                .map(authorities -> {
//                    log.info("{}", authorities);
//                    return new JwtAuthenticationToken(
//                            jwt,
//                            authorities,
//                            extractUsername(jwt)
//                    );
//                });
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.addFilterAfter((ServerWebExchange exchange, WebFilterChain chain) -> {
            log.info("security start");
            return chain.filter(exchange);
        }, SecurityWebFiltersOrder.FIRST);

        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable);

        http.oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                .jwt(jwtSpec -> {
                    jwtSpec.jwtAuthenticationConverter(this::convert);
                })
        );

//        http.oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
//                .jwt(jwtSpec -> jwtSpec
//                        .jwtAuthenticationConverter(this::convert)
//                )
//        );

        http.authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
                .pathMatchers("/401.html")
                .permitAll()
                .anyExchange()
                .hasAnyAuthority("admin")
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

    private String extractUsername(Jwt jwt) {
        return jwt.hasClaim(USERNAME_CLAIM) ? jwt.getClaimAsString(USERNAME_CLAIM) : jwt.getSubject();
    }
}
