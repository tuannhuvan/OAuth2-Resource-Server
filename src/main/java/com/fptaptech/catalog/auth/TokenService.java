package com.fptaptech.catalog.auth;

import com.fptaptech.catalog.config.JwkKeyManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class TokenService {

    private final JwtEncoder encoder;
    private final JwkKeyManager jwkKeyManager;
    private final TokenRevocationService tokenRevocationService;
    private final String issuer;
    private final Duration ttl;

    public TokenService(JwtEncoder encoder,
                        JwkKeyManager jwkKeyManager,
                        TokenRevocationService tokenRevocationService,
                        @Value("${app.jwt.issuer:catalog-api}") String issuer,
                        @Value("${app.jwt.ttl:15m}") Duration ttl) {
        this.encoder = encoder;
        this.jwkKeyManager = jwkKeyManager;
        this.tokenRevocationService = tokenRevocationService;
        this.issuer = issuer;
        this.ttl = ttl;
    }

    public TokenResponse issue(Authentication authentication, String refreshToken) {
        String username = authentication.getName();
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .toList();

        long tokenVersion = tokenRevocationService.getUserTokenVersion(username);
        return issueToken(username, roles, tokenVersion, refreshToken);
    }

    public TokenResponse issueToken(String username, List<String> roles, long tokenVersion, String refreshToken) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(ttl);
        String jti = UUID.randomUUID().toString();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(expiresAt)
                .subject(username)
                .id(jti)
                .claim("roles", roles)
                .claim("ver", tokenVersion)
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(jwkKeyManager.getActiveKid())
                .build();

        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenResponse(token, refreshToken, "Bearer", ttl.toSeconds());
    }

    public Duration getTtl() {
        return ttl;
    }
}
