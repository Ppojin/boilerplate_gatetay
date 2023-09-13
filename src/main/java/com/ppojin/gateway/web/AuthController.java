package com.ppojin.gateway.web;

import feign.form.FormEncoder;
import feign.json.JsonDecoder;
import feign.reactive.ReactorFeign;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;

@RestController
@Slf4j
public class AuthController {
    private final String clientSecret;
    private final String hostName;
    private final KeycloakOauthToken keycloakOauthToken;

    public AuthController(
            @Value("${ppojin_gw.keycloak.client-secret}") String clientSecret,
            @Value("${ppojin_gw.hostname}") String hostName,
            @Value("${ppojin_gw.keycloak.uri}") String keycloakUri
    ) {
        this.clientSecret = clientSecret;
        this.hostName = hostName;

        this.keycloakOauthToken = ReactorFeign.builder()
                .decoder(new JsonDecoder())
                // TODO: feign.codec.DecodeException: class sun.reflect.generics.reflectiveObjects.ParameterizedTypeImpl cannot be cast to class java.lang.Class
                .target(KeycloakOauthToken.class, keycloakUri);
    }

    @GetMapping("/auth/**")
    Mono<ResponseEntity<Void>> codeToJwt(
            @RequestParam("code") String code,
            @RequestParam("session_state") String session_state,
            ServerHttpRequest request
    ) {
        RequestPath path = request.getPath();
        String redirectUri = hostName + path.toString().substring(0);

        KeycloakOauthToken.KeyCloakTokenRequest keyCloakTokenRequest = new KeycloakOauthToken.KeyCloakTokenRequest(
                code, redirectUri, clientSecret
        );


        return keycloakOauthToken.keycloakOauth(keyCloakTokenRequest.getFormBodyStr())
                .map((KeycloakOauthToken.KeycloakTokenResponse response) -> ResponseEntity
                        .status(HttpStatus.MOVED_PERMANENTLY)
                        .location(URI.create(redirectUri))
                        .headers(h -> {
                            ResponseCookie refreshToken = ResponseCookie.fromClientResponse(
                                            "X-REFRESH-TOKEN",
                                            response.getRefreshToken()
                                    )
                                    .maxAge(response.getRefreshExpiresIn())
                                    .httpOnly(true)
                                    .path("/")
                                    .secure(false) // should be true in production
                                    .build();
                            ResponseCookie accessToken = ResponseCookie.fromClientResponse(
                                            "X-ACCESS-TOKEN",
                                            response.getAccessToken()
                                    )
                                    .maxAge(response.getExpiresIn())
                                    .httpOnly(false)
                                    .path("/")
                                    .secure(false) // should be true in production
                                    .build();
                            h.add("Set-Cookie", refreshToken.toString());
                            h.add("Set-Cookie", accessToken.toString());
                        }).build());
    }
}
