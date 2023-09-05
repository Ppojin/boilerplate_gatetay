package com.ppojin.gateway.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfiguration {

    private final String keycloakURI;
    private final String httpbinURI;
    private final LoggingFilter loggingFilter;

    public GatewayConfiguration(
            @Value("${ppojin_gw.keycloak.uri}") String keycloakURI,
            @Value("${ppojin_gw.httpbin.uri}") String httpbinURI,
            LoggingFilter loggingFilter
    ) {
        this.keycloakURI = keycloakURI;
        this.httpbinURI = httpbinURI;
        this.loggingFilter = loggingFilter;
    }


    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                /*
                spring.cloud.gateway.routes[0].id=http-bin
                spring.cloud.gateway.routes[0].uri=http://localhost:8888
                spring.cloud.gateway.routes[0].predicates=["Path=\/httpbin\/**"]
                spring.cloud.gateway.routes[0].filters[1].name=LoggingFilter
                spring.cloud.gateway.routes[0].filters[1].args.baseMessage=My Custom Message
                spring.cloud.gateway.routes[0].filters[1].args.postLogger=true
                spring.cloud.gateway.routes[0].filters[1].args.preLogger=true
                */
                .route("http-bin", r -> r
                        .path("/httpbin/**")
                        .filters(f -> f.rewritePath("/httpbin(?<segment>/?.*)", "$\\{segment}")
                                .filter(loggingFilter.apply(args -> {
                                    args.setBaseMessage("My Custom Message");
                                    args.setPreLogger(true);
                                    args.setPostLogger(true);
                                }))
                        )
                        .uri(httpbinURI)
                )
                .build();
    }
}
