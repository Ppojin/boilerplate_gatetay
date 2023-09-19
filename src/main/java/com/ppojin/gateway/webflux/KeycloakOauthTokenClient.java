package com.ppojin.gateway.webflux;

import com.fasterxml.jackson.annotation.JsonProperty;
import feign.Headers;
import feign.RequestLine;
import lombok.*;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;

public interface KeycloakOauthTokenClient {
    @RequestLine("POST /realms/ppojin/protocol/openid-connect/token")
    @Headers({
            "Content-Type: " + MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            "Accept: " + MediaType.APPLICATION_JSON_VALUE
    })
    TokenDTO getToken(
        @RequestBody String body
    );

    @Getter
    static class RequestBodyWithRefreshToken {
        private final String grantType = "refresh_token";
        private final String clientId = "test-api";
        private final String refreshToken;
        private final String clientSecret;

        public RequestBodyWithRefreshToken(String refreshToken, String clientSecret) {
            this.refreshToken = refreshToken;
            this.clientSecret = clientSecret;
        }

        public String getFormBodyStr(){
            return "grant_type="        + grantType +
                    "&client_id="        + clientId +
                    "&refresh_token="     + refreshToken +
                    "&client_secret="    + clientSecret;
        }
    }

    @Getter
    static class RequestBodyWithAuthorizationCode {
        private final String grantType = "authorization_code";
        private final String clientId = "test-api";
        private final String code;
        private final String redirectUri;
        private final String clientSecret;

        public RequestBodyWithAuthorizationCode(String code, String redirectUri, String clientSecret) {
            this.code = code;
            this.redirectUri = redirectUri;
            this.clientSecret = clientSecret;
        }

        public String getFormBodyStr(){
            return "grant_type="        + grantType +
                   "&client_id="        + clientId +
                   "&code="             + code +
                   "&redirect_uri="     + redirectUri +
                   "&client_secret="    + clientSecret;
        }
    }
}
