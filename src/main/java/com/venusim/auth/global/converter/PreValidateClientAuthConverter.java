package com.venusim.auth.global.converter;

import com.querydsl.core.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

@Component
public class PreValidateClientAuthConverter implements AuthenticationConverter {

    @Value("${app.issuer}")
    private String issuer;

    @Override
    public Authentication convert(HttpServletRequest request) {

        // Authorization 헤더 유무 확인
        boolean hasAuthHeader = !StringUtils.isNullOrEmpty(request.getHeader("Authorization"));
        if (!hasAuthHeader) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_CLIENT,
                            "Missing or invalid header: Authorization",
                            issuer
                    )
            );
        }

        String uri = request.getRequestURI();

        if(uri.startsWith("/oauth2/token")) {
            boolean hasGrantType = !StringUtils.isNullOrEmpty(request.getParameter("grant_type"));

            if (!hasGrantType) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(
                                OAuth2ErrorCodes.INVALID_REQUEST,
                                "Missing or invalid parameter: grant_type",
                                issuer
                        )
                );
            }
        }

        if (uri.startsWith("/oauth2/revoke") || uri.startsWith("/oauth2/introspect")) {
            if (request.getParameter("token") == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "Missing or invalid parameter: token",
                        "https://t-auth.vsaidt.com"
                ));
            }
        }

        return null;
    }
}