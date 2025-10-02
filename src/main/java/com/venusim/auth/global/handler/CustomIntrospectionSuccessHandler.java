package com.venusim.auth.global.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.venusim.auth.global.util.AuthUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;


@Component
public class CustomIntrospectionSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthUtil authUtil;

    public CustomIntrospectionSuccessHandler(AuthUtil authUtil) {
        this.authUtil = authUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {

        OAuth2TokenIntrospectionAuthenticationToken tokenAuth = (OAuth2TokenIntrospectionAuthenticationToken) authentication;
        OAuth2TokenIntrospection claims = tokenAuth.getTokenClaims();

        boolean active = claims != null && claims.isActive();
        if (!active) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_TOKEN,
                    "Token is inactive or expired.",
                    "https://t-auth.vsaidt.com"
            ));
        }

        try {
            objectMapper.registerModule(new JavaTimeModule());
            Map<String, Object> body = new LinkedHashMap<>(claims.getClaims());
            String json = objectMapper.writeValueAsString(body);
            authUtil.encodeResponse(response, json);
        } catch (IOException e) {
            throw new RuntimeException("Failed to build encrypted token response", e);
        }
    }
}
