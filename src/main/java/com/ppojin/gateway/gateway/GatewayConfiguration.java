package com.ppojin.gateway.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.PredicateSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfiguration {

    private final String httpbinURI;
    private final LoggingFilter loggingFilter;

    public GatewayConfiguration(
            @Value("${ppojin_gw.httpbin.uri}") String httpbinURI,
            LoggingFilter loggingFilter
    ) {
        this.httpbinURI = httpbinURI;
        this.loggingFilter = loggingFilter;
    }


    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("http-bin", p -> p
                        .path("/httpbin/**")
                        .filters(f->f
                                .rewritePath("httpbin(?<segment>/?.*)", "$\\{segment}")
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
