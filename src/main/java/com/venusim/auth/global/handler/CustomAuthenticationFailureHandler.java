package com.venusim.auth.global.handler;

import com.venusim.auth.global.util.AuthUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final AuthUtil authUtil;

    public CustomAuthenticationFailureHandler(AuthUtil authUtil) {
        this.authUtil = authUtil;
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) {

        String code;
        String desc;
        int status;
        boolean addWwwAuth;
        try {
            if (exception instanceof OAuth2AuthenticationException authEx) {
                code = authEx.getError().getErrorCode();
                desc = Optional.ofNullable(authEx.getError().getDescription())
                        .filter(s -> !s.isBlank())
                        .orElseGet(exception::getMessage);

                status = switch (code) {
                    case OAuth2ErrorCodes.INVALID_REQUEST,
                         OAuth2ErrorCodes.INVALID_GRANT,
                         OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
                         OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE -> 400;
                    case OAuth2ErrorCodes.INVALID_CLIENT,
                         OAuth2ErrorCodes.INVALID_TOKEN,
                         "user_not_allowed" -> 401;
                    case OAuth2ErrorCodes.ACCESS_DENIED -> 403;
                    case OAuth2ErrorCodes.SERVER_ERROR -> 500;
                    default -> 503;
                };
                addWwwAuth = OAuth2ErrorCodes.INVALID_CLIENT.equals(code);
            } else {
                // 사용자 정의 아님 -> 스프링 기본 예외를 표준 응답으로 매핑
                AuthExceptionMapper.Mapped m = AuthExceptionMapper.map(exception);
                code = m.code;
                desc = m.desc;
                status = m.http;
                addWwwAuth = m.wwwAuth;
            }

            if (addWwwAuth && status == 401) {
                response.addHeader("WWW-Authenticate", "Basic realm=\"oauth2/token\"");
            }

            response.setStatus(status);

            String json = "{\"error\":\"%s\",\"description\":\"%s\"}".formatted(code, desc);
            authUtil.encodeResponse(response, json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build encrypted token response", e);
        }
    }
}

