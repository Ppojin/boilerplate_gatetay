package com.ppojin.gateway.security;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.Serial;
import java.util.Collection;
import java.util.Objects;

@Getter
public class KeycloakAuthenticationToken extends JwtAuthenticationToken {
    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String name;

    protected KeycloakAuthenticationToken(Jwt token, Collection<GrantedAuthority> authorities) {
        super(token, authorities);
        this.name = Objects.requireNonNullElse(
                token.getClaimAsString("preferred_username"),
                token.getSubject()
        );
    }
}