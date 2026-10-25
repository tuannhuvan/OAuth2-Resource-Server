package com.fptaptech.catalog.auth;

import java.time.Instant;
import java.util.List;

public record UserSummaryResponse(
        String username,
        List<String> roles,
        Instant expiresAt
) {
}
