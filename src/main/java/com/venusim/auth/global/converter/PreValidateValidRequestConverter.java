package com.venusim.auth.global.converter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

@Component
public class PreValidateValidRequestConverter implements AuthenticationConverter {
    
    @Value("${app.issuer}")
    private String issuer;
    
    @Override
    public Authentication convert(HttpServletRequest request) {

        String token = request.getParameter(OAuth2ParameterNames.TOKEN);
        if (token == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_TOKEN,
                "Missing or invalid parameter: token",
                issuer
            ));
        }

        /*String tokenTypeHint = request.getParameter(OAuth2ParameterNames.TOKEN_TYPE_HINT);
        if (tokenTypeHint == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "Missing or invalid parameter: token_type_hint",
                    issuer
            ));
        }*/

        return null;
    }
}
