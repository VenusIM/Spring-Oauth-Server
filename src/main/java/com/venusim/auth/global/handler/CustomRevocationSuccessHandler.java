package com.venusim.auth.global.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.venusim.auth.global.util.AuthUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;


@Component
public class CustomRevocationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthUtil authUtil;

    public CustomRevocationSuccessHandler(AuthUtil authUtil) {
        this.authUtil = authUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {
        try {
            OAuth2TokenRevocationAuthenticationToken tokenAuth = (OAuth2TokenRevocationAuthenticationToken) authentication;
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("revoked", true);
            payload.put("token", tokenAuth.getToken());                   // 선택
            payload.put("token_type_hint", tokenAuth.getTokenTypeHint()); // 선택

            String json = objectMapper.writeValueAsString(payload);
            authUtil.encodeResponse(response, json);

        } catch (Exception e) {
            throw new RuntimeException("Failed to build encrypted token response", e);
        }
    }
}
