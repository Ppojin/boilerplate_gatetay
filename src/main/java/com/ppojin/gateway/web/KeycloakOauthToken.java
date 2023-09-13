package com.ppojin.gateway.web;

import com.fasterxml.jackson.annotation.JsonProperty;
import feign.Headers;
import feign.RequestLine;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import reactor.core.publisher.Mono;

public interface KeycloakOauthToken {
    @RequestLine("POST /realms/ppojin/protocol/openid-connect/token")
    @Headers("Content-Type: " + MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    Mono<KeycloakTokenResponse> keycloakOauth(
//        @RequestBody KeyCloakTokenRequest requestBody
        @RequestBody String body
    );

    @Getter
    @RequiredArgsConstructor
    class KeycloakTokenResponse {
        @JsonProperty("access_token")
        private final String accessToken;
        @JsonProperty("expires_in")
        private final Integer expiresIn;
        @JsonProperty("refresh_expires_in")
        private final Integer refreshExpiresIn;
        @JsonProperty("refresh_token")
        private final String refreshToken;
        @JsonProperty("token_type")
        private final String tokenType;
        @JsonProperty("not_before_policy")
        private final Integer notBeforePolicy;
        @JsonProperty("session_state")
        private final String sessionState;
        @JsonProperty("scope")
        private final String scope;
    }

    @Getter
    class KeyCloakTokenRequest {
        private final String grantType = "authorization_code";
        private final String clientId = "test-api";
        private final String code;
        private final String redirectUri;
        private final String clientSecret;

        public KeyCloakTokenRequest(String code, String redirectUri, String clientSecret) {
            this.code = code;
            this.redirectUri = redirectUri;
            this.clientSecret = clientSecret;
        }

        public String getFormBodyStr(){
            return "grant_type="        + grantType +
                    "&client_id="      + clientId +
                    "&code="            + code +
                    "&redirect_uri="    + redirectUri +
                    "&client_secret="   + clientSecret;
        }
    }
}
