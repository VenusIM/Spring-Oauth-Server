package com.venusim.auth.global.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.venusim.auth.global.util.AuthUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthUtil authUtil;

    public CustomAuthenticationSuccessHandler(AuthUtil authUtil) {
        this.authUtil = authUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {
        try {
            OAuth2AccessTokenAuthenticationToken tokenAuth = (OAuth2AccessTokenAuthenticationToken) authentication;
            OAuth2AccessToken accessToken = tokenAuth.getAccessToken();
            OAuth2RefreshToken refreshToken = tokenAuth.getRefreshToken();
            Map<String, Object> additional = tokenAuth.getAdditionalParameters();

            // payload 구성
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("access_token", accessToken.getTokenValue());
            payload.put("token_type", accessToken.getTokenType().getValue());
            payload.put("expires_in",
                    Duration.between(Instant.now(), accessToken.getExpiresAt()).getSeconds());
            if (refreshToken != null) {
                payload.put("refresh_token", refreshToken.getTokenValue());
            }
            payload.putAll(additional);

            // 직렬화 → 암호화 + Base64
            String json = objectMapper.writeValueAsString(payload);
            authUtil.encodeResponse(response, json);

            String s = "token="+accessToken.getTokenValue()+ "&token_type_hint=access_token";
            System.out.println(authUtil.encryptBase64(s));

        } catch (Exception e) {
            throw new RuntimeException("Failed to build encrypted token response", e);
        }
    }
}
