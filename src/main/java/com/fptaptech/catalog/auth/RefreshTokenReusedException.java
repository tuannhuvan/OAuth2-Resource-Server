package com.fptaptech.catalog.auth;

public class RefreshTokenReusedException extends RuntimeException {
    public RefreshTokenReusedException(String message) {
        super(message);
    }
}
