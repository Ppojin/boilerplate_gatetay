package com.ppojin.gateway.gateway;

import com.ppojin.gateway.security.KeycloakAuthenticationConverter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Slf4j
public class JwtAuthorizationGlobalFilter implements GlobalFilter, Ordered {

    private final KeycloakAuthenticationConverter keycloakAuthenticationConverter;
    private final NimbusJwtDecoder jwtDecoder;

    public JwtAuthorizationGlobalFilter(
            KeycloakAuthenticationConverter keycloakAuthenticationConverter,
            @Value("${spring.security.oauth2.resource-server.jwt.jwk-set-uri}") String jwkSetUri
    ) {
        this.keycloakAuthenticationConverter = keycloakAuthenticationConverter;
        this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("Global Pre Filter executed");
        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();

        List<String> authHeader = headers.get("Authorization");
        if (authHeader != null) {
            Jwt jwt = authHeader.stream()
                    .filter((String h) -> h.startsWith("Bearer "))
                    .map((h)->{
                        String token = h.substring(7);
                        return jwtDecoder.decode(token);
                    })
                    .findFirst()
                    .orElseThrow();
            String[] roles = keycloakAuthenticationConverter.keycloakClientRoles(jwt)
                    .toArray(String[]::new);
            List<String> tenants = jwt.getClaim("tenant");
            exchange.getRequest().mutate()
                    .header("X-User-Role", roles)
                    .header("X-User-Id", (String) jwt.getClaim("sub"))
                    .header("X-User-Tenant", tenants.toArray(String[]::new))
                    .build();
        }

        return chain.filter(exchange)
                .then(Mono.fromRunnable(() -> {
                    log.info("Last Post Global Filter");
                }));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
