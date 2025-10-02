package com.venusim.auth.global.converter;

import com.venusim.auth.domain.member.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class PreValidateTokenRequestConverter implements AuthenticationConverter {

    private final MemberService memberService;
    
    @Value("${app.issuer}")
    private String issuer;

    @Autowired
    public PreValidateTokenRequestConverter(MemberService memberService) {
        this.memberService = memberService;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        // 1) 필요시 grant_type별 조건 분기 (예: 특정 grant, scope 에만 userId 요구)
        String grantType = request.getParameter("grant_type");
        if (grantType == null || grantType.isBlank()) {
            // 파라미터가 없는 케이스 → invalid_request
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "Missing parameter: grant_type",
                    issuer
            ));
        }

        if (!"client_credentials".equals(grantType)) {
            // 파라미터는 있으나 지원하지 않음 → unsupported_grant_type
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE,
                    "Unsupported grant_type: " + grantType,
                    issuer
            ));
        }

        // 2) userId 존재/형식 검증
        String userId = trimToNull(request.getParameter("memid"));
        if (userId == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "Missing or invalid parameter: memid",
                    issuer
            ));
        }

        String tmpPassword = trimToNull(request.getParameter("tmpkey"));
        if (tmpPassword == null) {
            // RFC 6749 상 "invalid_request"가 맞습니다 (기존 코드의 INVALID_CLIENT → INVALID_REQUEST로 교정)
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "Missing or invalid parameter: tmpkey",
                    issuer
            ));
        }

        if (!memberService.isValid(userId, tmpPassword)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    "user_not_allowed",
                    "User is not allowed to obtain a token.",
                    issuer
            ));
        }

        return null;
    }

    private static String trimToNull(String v) {
        return Optional.ofNullable(v)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .orElse(null);
    }
}
