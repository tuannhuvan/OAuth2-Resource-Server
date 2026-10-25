package com.fptaptech.catalog.config;

import com.fptaptech.catalog.auth.TokenRevocationService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class TokenRevocationValidator implements OAuth2TokenValidator<Jwt> {

    private final TokenRevocationService tokenRevocationService;

    public TokenRevocationValidator(TokenRevocationService tokenRevocationService) {
        this.tokenRevocationService = tokenRevocationService;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        // 1. Check if JTI was blacklisted via single logout
        if (tokenRevocationService.isJtiRevoked(jwt.getId())) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "Access token đã bị thu hồi do đăng xuất (Logged out)",
                    null
            ));
        }

        // 2. Check token version for logout-all and change-password
        Long tokenVer = jwt.getClaim("ver");
        String username = jwt.getSubject();
        if (!tokenRevocationService.isTokenVersionValid(username, tokenVer)) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token",
                    "Phiên token không còn hiệu lực do đổi mật khẩu hoặc đăng xuất toàn bộ thiết bị",
                    null
            ));
        }

        return OAuth2TokenValidatorResult.success();
    }
}
