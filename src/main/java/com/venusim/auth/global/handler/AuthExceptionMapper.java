package com.venusim.auth.global.handler;

import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.www.NonceExpiredException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

final class AuthExceptionMapper {

    static final class Mapped {
        final String code;     // OAuth2ErrorCodes.*
        final int http;        // HTTP status
        final String desc;     // description
        final boolean wwwAuth; // 401일 때 WWW-Authenticate 추가 여부

        Mapped(String code, int http, String desc, boolean wwwAuth) {
            this.code = code; this.http = http; this.desc = desc; this.wwwAuth = wwwAuth;
        }
    }

    private static final Map<Class<? extends AuthenticationException>, Function<AuthenticationException, Mapped>> RULES = new LinkedHashMap<>();

    static {
        // 클라이언트 인증 실패 계열 -> 401 invalid_client
        RULES.put(BadCredentialsException.class, ex ->
                new Mapped(OAuth2ErrorCodes.INVALID_CLIENT, 401, "Invalid client credentials.", true));
        RULES.put(UsernameNotFoundException.class, ex ->
                new Mapped(OAuth2ErrorCodes.INVALID_CLIENT, 401, "Client not found.", true));
        RULES.put(AccountStatusException.class, ex ->
                new Mapped(OAuth2ErrorCodes.ACCESS_DENIED, 403, "Account status prevents authentication.", false));

        // 요청이 불완전 / 자격증명 누락 -> 400 invalid_request
        RULES.put(InsufficientAuthenticationException.class, ex ->
                new Mapped(OAuth2ErrorCodes.INVALID_REQUEST, 400, "Missing or insufficient authentication.", false));
        RULES.put(NonceExpiredException.class, ex ->
                new Mapped(OAuth2ErrorCodes.INVALID_REQUEST, 400, "Nonce expired.", false));

        // 내부 서비스 오류 -> 500 server_error
        RULES.put(AuthenticationServiceException.class, ex ->
                new Mapped(OAuth2ErrorCodes.SERVER_ERROR, 500, "Authentication service error.", false));
    }

    static Mapped map(AuthenticationException ex) {
        for (Map.Entry<Class<? extends AuthenticationException>, Function<AuthenticationException, Mapped>> e : RULES.entrySet()) {
            if (e.getKey().isInstance(ex)) return e.getValue().apply(ex);
        }
        // 기본값: RFC에 맞춰 401 or 400 중 하나로 갈 수도 있지만,
        // "무슨 예외인지 모르면 서버 내부 오류" 쪽이 안전
        return new Mapped(OAuth2ErrorCodes.SERVER_ERROR, 500, "Unhandled authentication error.", false);
    }

    private AuthExceptionMapper() {}
}
