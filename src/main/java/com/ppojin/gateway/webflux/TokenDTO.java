package com.ppojin.gateway.webflux;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.web.server.Cookie;
import org.springframework.http.ResponseCookie;

import java.util.Arrays;
import java.util.List;


@Getter
@Setter
@NoArgsConstructor
public class TokenDTO {
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

    public List<ResponseCookie> getCookieList() {
        return List.of(
                ResponseCookie.fromClientResponse(
                                "X-REFRESH-TOKEN",
                                refreshToken
                        )
                        .maxAge(refreshExpiresIn)
                        .httpOnly(true)
                        .path("/refresh")
                        .secure(true) // should be true in production
                        .sameSite(Cookie.SameSite.NONE.attributeValue())
                        .build(),
                ResponseCookie.fromClientResponse(
                                "X-ACCESS-TOKEN",
                                accessToken
                        )
                        .maxAge(expiresIn)
                        .httpOnly(false)
                        .path("/")
                        .secure(false) // should be true in production
                        .build()
        );
    }
}
