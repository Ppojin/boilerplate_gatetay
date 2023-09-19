package com.ppojin.gateway.webflux;

import com.ppojin.gateway.webflux.KeycloakOauthTokenClient.RequestBodyWithAuthorizationCode;
import com.ppojin.gateway.webflux.KeycloakOauthTokenClient.RequestBodyWithRefreshToken;
import feign.Logger;
import feign.Retryer;
import feign.jackson.JacksonDecoder;
import feign.reactive.ReactorFeign;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class TokenService {
    private final KeycloakOauthTokenClient keycloakOauthTokenClient;
    private final String clientSecret;

    public TokenService(
            @Value("${ppojin_gw.keycloak.client-secret}") String clientSecret,
            @Value("${ppojin_gw.keycloak.uri}") String keycloakUri
    ) {
        this.clientSecret = clientSecret;
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

    public TokenDTO getTokenWithRefreshToken(String refreshToken){
        var requestBody = new RequestBodyWithRefreshToken(refreshToken, clientSecret);
        return this.keycloakOauthTokenClient.getToken(requestBody.getFormBodyStr());
    }

    public TokenDTO getTokenWithAuthorizationCode(String code, String redirectUri){
        var requestBody = new RequestBodyWithAuthorizationCode(code, redirectUri, clientSecret);
        return this.keycloakOauthTokenClient.getToken(requestBody.getFormBodyStr());
    }
}
