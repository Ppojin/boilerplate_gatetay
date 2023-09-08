package com.ppojin.gateway.security;

import java.util.*;
import java.util.stream.Collectors;

import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
public class KeycloakAuthenticationConverter implements Converter<Jwt, Mono<KeycloakAuthenticationToken>> {
    private static final String REALM_ACCESS = "realm_access";
    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String ROLES = "roles";

    private final String clientId;

    public KeycloakAuthenticationConverter(@Value("${app.security.clientId}") String clientId) {
        if (StringUtils.isBlank(clientId)) {
            throw new RuntimeException("Must set client id on properties");
        }

        this.clientId = clientId;
    }

    @Override
    public Mono<KeycloakAuthenticationToken> convert(@NonNull Jwt jwt) {
        return Mono.just(jwt).map((token)->{
            log.info("[KeycloakAuthenticationConverter] convert key");
            Collection<GrantedAuthority> authorities = keycloakClientRoles(token)
                    .stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());

            log.info("[KeycloakAuthenticationConverter] authorities: {}", authorities);
            return new KeycloakAuthenticationToken(token, authorities);
        });
    }

    public List<String> keycloakClientRoles(Jwt jwt) {
        Map<String, Map<String, List<String>>> resource_access = jwt.getClaim(RESOURCE_ACCESS);
        if (Objects.isNull(resource_access)){
            return Collections.emptyList();
        }

        Map<String, List<String>> clientRoles = resource_access.get(clientId);
        if (Objects.isNull(clientRoles)){
            return Collections.emptyList();
        }

        return clientRoles.get(ROLES);
    }

    public List<String> keycloakRealmRoles(Jwt jwt) {
        Map<String, List<String>> realm_access = jwt.getClaim(REALM_ACCESS);
        if (Objects.isNull(realm_access)){
            return Collections.emptyList();
        }

        return realm_access.get(ROLES);
    }
}