package com.ppojin.gateway.webflux;

import feign.Logger;
import feign.Retryer;
import feign.jackson.JacksonDecoder;
import feign.reactive.ReactorFeign;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@RestController
@Slf4j
public class AuthController {
    private final String clientSecret;
    private final RedirectUri redirectUri;
    private final KeycloakOauthTokenClient keycloakOauthTokenClient;

    public AuthController(
            @Value("${ppojin_gw.keycloak.client-secret}") String clientSecret,
            @Value("${ppojin_gw.hostname}") String hostName,
            @Value("${ppojin_gw.keycloak.uri}") String keycloakUri
    ) {
        this.clientSecret = clientSecret;
        this.redirectUri = new RedirectUri(hostName);
        this.keycloakOauthTokenClient = ReactorFeign.builder()
                .decoder(new JacksonDecoder())
                .logger(new Logger() {
                    @Override
                    protected void log(String configKey, String format, Object... args) {
                        System.out.printf(methodTag(configKey) + format + "%n", args);
                    }
                })
                .logLevel(Logger.Level.FULL)
                .retryer(new Retryer.Default(100L, TimeUnit.SECONDS.toMillis(3L), 1))
                .target(KeycloakOauthTokenClient.class, keycloakUri);
    }

    @GetMapping({"/token/**", "/token"})
    Mono<ResponseEntity<Void>> codeToJwt(
            @RequestParam("code") String code,
            @RequestParam("session_state") String session_state,
            ServerHttpRequest request
    ) {
        String redirectUriForClient = redirectUri.getRedirectUriForClient(request);
        return Mono
                .just(new KeycloakOauthTokenClient.Request(
                        code,
                        redirectUri.getRedirectUriForKeycloak(request),
                        clientSecret
                ))
                .map(body -> keycloakOauthTokenClient.getToken(body.getFormBodyStr()))
                .map((KeycloakOauthTokenClient.Response tokenResponse) -> ResponseEntity
                        .status(HttpStatus.MOVED_PERMANENTLY)
                        .location(URI.create(redirectUriForClient))
                        .headers((HttpHeaders h) -> {
                            ResponseCookie refreshToken = ResponseCookie.fromClientResponse(
                                            "X-REFRESH-TOKEN",
                                            tokenResponse.getRefreshToken()
                                    )
                                    .maxAge(tokenResponse.getRefreshExpiresIn())
                                    .httpOnly(true)
                                    .path("/")
                                    .secure(false) // should be true in production
                                    .build();
                            ResponseCookie accessToken = ResponseCookie.fromClientResponse(
                                            "X-ACCESS-TOKEN",
                                            tokenResponse.getAccessToken()
                                    )
                                    .maxAge(tokenResponse.getExpiresIn())
                                    .httpOnly(false)
                                    .path("/")
                                    .secure(false) // should be true in production
                                    .build();
                            h.add("Set-Cookie", refreshToken.toString());
                            h.add("Set-Cookie", accessToken.toString());
                        }).build());
    }

    static class RedirectUri {
        private static final Set<String> keycloakQueryParams = Set.of("session_state", "code");
        private final String hostName;

        public RedirectUri(String hostName) {
            this.hostName = hostName;
        }

        public String getRedirectUriForKeycloak(ServerHttpRequest request) {
            return getRedirectUri(request, 0, "%26");
        }

        public String getRedirectUriForClient(ServerHttpRequest request) {
            return getRedirectUri(request, 6, "&");
        }

        private String getRedirectUri(ServerHttpRequest request, int pathBeginIndex, String queryParamDelimiter) {
            MultiValueMap<String, String> queryParams = request.getQueryParams();
            RequestPath path = request.getPath();
            String redirectParam = getRedirectParam(queryParams, queryParamDelimiter);
            return this.hostName +
                    path.toString().substring(pathBeginIndex) +
                    (StringUtils.isEmpty(redirectParam) ? "" : ("?" + redirectParam));
        }

        private static String getRedirectParam(MultiValueMap<String, String> queryParams, String delimiter) {
            return queryParams.keySet()
                    .stream()
                    .filter(k -> !keycloakQueryParams.contains(k))
                    .flatMap(k -> queryParams.get(k).stream().map(v -> k + "=" + v))
                    .collect(Collectors.joining(delimiter));
        }
    }
}
