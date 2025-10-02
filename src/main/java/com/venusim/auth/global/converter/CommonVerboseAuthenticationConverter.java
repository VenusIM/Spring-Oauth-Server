package com.venusim.auth.global.converter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
public final class CommonVerboseAuthenticationConverter implements AuthenticationConverter {
    private static final String RFC7617 = "https://datatracker.ietf.org/doc/html/rfc7617";
    private static final String RFC6749_231 = "https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1";

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return null;
        }

        String[] parts = header.split("\\s+");
        if (!parts[0].equalsIgnoreCase("Basic")) {
            return null;
        }

        if (parts.length != 2) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST,
                            "Invalid Authorization header format. Must be basic auth with encoded credentials.",
                            RFC7617
                    )
            );
        }

        byte[] decodedCredentials;
        try {
            decodedCredentials = Base64.getDecoder().decode(parts[1].getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST,
                            "Invalid Authorization header format. Failed to decode credentials.",
                            RFC6749_231
                    )
            );
        }

        // 스펙상 'id:secret' (콜론 필수)
        String credentialsString = new String(decodedCredentials, StandardCharsets.UTF_8);
        int colon = credentialsString.indexOf(':');
        if (colon < 0) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_REQUEST,
                            "Invalid Authorization header format. Missing client_id and/or client_secret.",
                            RFC7617
                    )
            );
        }

        return null;
    }
}
