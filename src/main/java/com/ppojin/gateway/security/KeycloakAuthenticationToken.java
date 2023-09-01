package com.ppojin.gateway.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

import java.io.Serial;
import java.util.Collection;
import java.util.Map;

public class KeycloakAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    protected KeycloakAuthenticationToken(Jwt token, Collection<? extends GrantedAuthority> authorities) {
        super(token, authorities);
        this.setAuthenticated(true);
    }

    @Override
    public Map<String, Object> getTokenAttributes() {
        return this.getToken().getClaims();
    }
}