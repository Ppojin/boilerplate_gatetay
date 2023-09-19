package com.ppojin.gateway.gateway;

import com.ppojin.gateway.security.KeycloakAuthenticationConverter;
import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Objects;
import java.util.Set;

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
//        log.info("Global Pre Filter executed");
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
            ServerHttpRequest.Builder builder = exchange.getRequest().mutate();
            builder.header("X-User-Role", roles);
            builder.header("X-User-Id", Objects.requireNonNullElse(jwt.getClaim("sub"), ""));
            List<String> tenants = jwt.getClaim("tenant");
            if(!CollectionUtils.isEmpty(tenants)){
                builder.header("X-User-Tenant", tenants.toArray(String[]::new));
            }
            builder.build();
        }

        return chain.filter(exchange)
                .then(Mono.fromRunnable(() -> {
                    HttpMethod method = request.getMethod();
                    boolean isTargetMethod = method != HttpMethod.GET || method != HttpMethod.DELETE;
                    boolean isCachedRequest = exchange.getRequest() instanceof TracingFilter.Request;
                    if (isTargetMethod && isCachedRequest){
                        boolean isBlankBody = StringUtils.isBlank(((TracingFilter.Request) request).getCachedBody());
                        if (!isBlankBody){
                            HttpHeaders headers1 = request.getHeaders();
                            for(var key : headers1.keySet() ){
                                log.info("====> {}: {}", key, headers1.get(key));
                            }
                            log.info("request body : {}", ((TracingFilter.Request) request).getCachedBody());
                        }
                    }
//                    log.info("Last Post Global Filter");
                }));
    }

    @Override
    public int getOrder() {
        return 2;
    }
}
