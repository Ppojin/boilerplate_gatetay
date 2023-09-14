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
    Response getToken(
        @RequestBody String body
    );

    @Getter
    @Setter
    @NoArgsConstructor
    class Response {
        @JsonProperty("access_token")
        private String accessToken;
        @JsonProperty("expires_in")
        private Integer expiresIn;
        @JsonProperty("refresh_expires_in")
        private Integer refreshExpiresIn;
        @JsonProperty("refresh_token")
        private String refreshToken;
        @JsonProperty("token_type")
        private String tokenType;
        @JsonProperty("not_before_policy")
        private Integer notBeforePolicy;
        @JsonProperty("session_state")
        private String sessionState;
        @JsonProperty("scope")
        private String scope;
    }

    @Getter
    class Request {
        private final String grantType = "authorization_code";
        private final String clientId = "test-api";
        private final String code;
        private final String redirectUri;
        private final String clientSecret;

        public Request(String code, String redirectUri, String clientSecret) {
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
