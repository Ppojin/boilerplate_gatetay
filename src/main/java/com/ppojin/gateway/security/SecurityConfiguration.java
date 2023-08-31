package com.ppojin.gateway.security;


import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Objects;

@Slf4j
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Configuration
public class SecurityConfiguration {

    private static final String USERNAME_CLAIM = "preferred_username";

    private final Converter<Jwt, Flux<GrantedAuthority>> jwtGrantedAuthoritiesConverter;

    public SecurityConfiguration(Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
        this.jwtGrantedAuthoritiesConverter = new ReactiveJwtGrantedAuthoritiesConverterAdapter(
                jwtGrantedAuthoritiesConverter
        );
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.addFilterAfter(new JustLoggingAfterSecurity(), SecurityWebFiltersOrder.FIRST);

        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        http.httpBasic(ServerHttpSecurity.HttpBasicSpec::disable);

        http.oauth2ResourceServer(oAuth2ResourceServerSpec -> oAuth2ResourceServerSpec
                .jwt(jwtSpec -> jwtSpec
                        .jwtAuthenticationConverter(this::convert)
                )
        );

        http.authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
//                .pathMatchers("/index.html")
                .anyExchange()
                .hasAnyAuthority("user", "admin")
//                .authenticated()
//                .anyExchange().permitAll()
        );
        http.addFilterBefore(new JustLoggingBeforeSecurity(), SecurityWebFiltersOrder.LAST);

        return http.build();
    }

    @Slf4j
    static class JustLoggingAfterSecurity implements WebFilter{
        @Override
        public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
            log.info("start auth");
            return chain.filter(exchange);
        }
    }

    @Slf4j
    static class JustLoggingBeforeSecurity implements WebFilter{
        @Override
        public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
            log.info("end auth");
            return chain.filter(exchange);
        }
    }

    private Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        return Objects.requireNonNull(
                        this.jwtGrantedAuthoritiesConverter.convert(jwt)
                )
                .collectList()
                .map(authorities -> {
                    log.info("{}", authorities);
                    return new JwtAuthenticationToken(
                            jwt,
                            authorities,
                            extractUsername(jwt)
                    );
                });
    }

    private String extractUsername(Jwt jwt) {
        return jwt.hasClaim(USERNAME_CLAIM) ? jwt.getClaimAsString(USERNAME_CLAIM) : jwt.getSubject();
    }
}
