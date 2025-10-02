package com.venusim.auth.global.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.venusim.auth.global.util.AuthUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.util.Map;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;


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
        try {
            OAuth2TokenIntrospectionAuthenticationToken tokenAuth = (OAuth2TokenIntrospectionAuthenticationToken) authentication;
            Map<String, Object> claims = tokenAuth.getTokenClaims().getClaims();

            objectMapper.registerModule(new JavaTimeModule());
            String json = objectMapper.writeValueAsString(claims);
            authUtil.encodeResponse(response, json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build encrypted token response", e);
        }
    }
}
