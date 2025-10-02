package com.venusim.auth.domain;

import java.time.Instant;
import java.util.Set;

public record TokenRecord(
        String authId,
        String clientId,
        String principal,
        Set<String> scopes,
        Instant issuedAt,
        Instant expiresAt,
        String jti,
        boolean active
) {}