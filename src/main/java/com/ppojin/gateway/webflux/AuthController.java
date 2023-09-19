package com.ppojin.gateway.webflux;

import feign.FeignException;
import feign.Logger;
import feign.Retryer;
import feign.jackson.JacksonDecoder;
import feign.reactive.ReactorFeign;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@RestController
@Slf4j
public class AuthController {
    private final RedirectUri redirectUri;
    private final TokenService tokenService;

    public AuthController(
            @Value("${ppojin_gw.hostname}") String hostName,
            TokenService tokenService
    ) {
        this.redirectUri = new RedirectUri(hostName);
        this.tokenService = tokenService;
    }

    @GetMapping({"/refresh"})
    Mono<ResponseEntity<Void>> tokenRefresh(
            ServerHttpRequest request
    ) {
        List<HttpCookie> refreshTokenCookies = request.getCookies().get("X-REFRESH-TOKEN");
        return Mono
                .just(refreshTokenCookies.get(0).getValue())
                .map(tokenService::getTokenWithRefreshToken)
                .map((TokenDTO tokenResponse) -> ResponseEntity.ok()
                        .headers(httpHeaders -> {
                            tokenResponse.getCookieList()
                                    .forEach(responseCookie -> {
                                        httpHeaders.add("Set-Cookie", responseCookie.toString());
                                    });
                        }).build());
    }

    @GetMapping({"/token/**", "/token"})
    Mono<ResponseEntity<Void>> codeToJwt(
            @RequestParam("code") String code,
            @RequestParam("session_state") String session_state,
            ServerHttpRequest request
    ) {
        String redirectUriForClient = redirectUri.getRedirectUriForClient(request);
        return Mono
                .just(List.of(code, redirectUri.getRedirectUriForKeycloak(request)))
                .map(body -> this.tokenService.getTokenWithAuthorizationCode(
                        body.get(0), body.get(1)
                ))
                .map((TokenDTO tokenResponse) -> ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY)
                        .location(URI.create(redirectUriForClient))
                        .headers(httpHeaders -> {
                            tokenResponse.getCookieList()
                                    .forEach(responseCookie -> {
                                        httpHeaders.add("Set-Cookie", responseCookie.toString());
                                    });
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
