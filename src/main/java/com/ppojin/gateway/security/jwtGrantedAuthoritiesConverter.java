package com.ppojin.gateway.security;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Configuration
@Slf4j
public class jwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private static final String ROLES = "roles";
    private static final String CLAIM_REALM_ACCESS = "realm_access";
    private static final String RESOURCE_ACCESS = "resource_access";

    private final Converter<Jwt, Collection<GrantedAuthority>> defaultAuthoritiesConverter;
    private final String clientId;

    public jwtGrantedAuthoritiesConverter(
            @Value("${app.security.clientId}") String clientId
    ) {
        this.clientId = clientId;
        this.defaultAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    }

    @Override
    public Collection<GrantedAuthority> convert(@NonNull Jwt jwt) {
        List<String> realmRoles = realmRoles(jwt);
        List<String> clientRoles = clientRoles(jwt, clientId);

        log.info("convert");
        Collection<GrantedAuthority> authorities = Stream
                .concat(realmRoles.stream(), clientRoles.stream())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        authorities.addAll(defaultGrantedAuthorities(jwt));

        return authorities;
    }

    private Collection<GrantedAuthority> defaultGrantedAuthorities(Jwt jwt) {
        return Optional
                .ofNullable(defaultAuthoritiesConverter.convert(jwt))
                .orElse(emptySet());
    }

    private List<String> realmRoles(Jwt jwt) {
        Optional<Map<String, List<String>>> claim = Optional
                .ofNullable(jwt.getClaim(CLAIM_REALM_ACCESS));

        return claim.map((var realmAccess) -> realmAccess.get(ROLES))
                .orElse(emptyList());
    }

    private List<String> clientRoles(Jwt jwt, String clientId) {
        if (ObjectUtils.isEmpty(clientId)) {
            return emptyList();
        }

        Optional<Map<String, Map<String, List<String>>>> claim = Optional
                .ofNullable(jwt.getClaim(RESOURCE_ACCESS));

        return claim
                .map(resourceAccess -> resourceAccess.get(clientId))
                .map(clientAccess -> clientAccess.get(ROLES))
                .orElse(emptyList());
    }
}