package com.venusim.auth.global.config;

import com.venusim.auth.global.filter.TokenBodyDecryptFilter;
import com.venusim.auth.global.handler.CustomAuthenticationFailureHandler;
import com.venusim.auth.global.handler.CustomIntrospectionSuccessHandler;
import com.venusim.auth.global.handler.CustomRevocationSuccessHandler;
import com.venusim.auth.global.util.PreValidateTokenRequestConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.venusim.auth.global.handler.CustomAuthenticationSuccessHandler;

import java.time.Duration;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Value("${app.issuer}")
    String issuer;

    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final CustomIntrospectionSuccessHandler customIntrospectionSuccessHandler;
    private final CustomRevocationSuccessHandler customRevocationSuccessHandler;

    @Autowired
    public SecurityConfig(CustomAuthenticationFailureHandler customAuthenticationFailureHandler, CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler, CustomIntrospectionSuccessHandler customIntrospectionSuccessHandler, CustomRevocationSuccessHandler customRevocationSuccessHandler) {
        this.customAuthenticationFailureHandler = customAuthenticationFailureHandler;
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
        this.customIntrospectionSuccessHandler = customIntrospectionSuccessHandler;
        this.customRevocationSuccessHandler = customRevocationSuccessHandler;
    }

    @Bean
    @Order(1)
    SecurityFilterChain asSecurity(HttpSecurity http,
                                   PreValidateTokenRequestConverter preValidateTokenRequestConverter) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        RequestMatcher asEndpoints = authorizationServer.getEndpointsMatcher();
        http.securityMatcher(asEndpoints);
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // (4) 토큰 엔드포인트 커스터마이징: 추가 파라미터 사전 검증 Provider 삽입
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .clientAuthentication(oAuth2ClientAuthenticationConfigurer -> oAuth2ClientAuthenticationConfigurer
                        .errorResponseHandler(customAuthenticationFailureHandler)
                ).tokenEndpoint(token -> token
                        .accessTokenRequestConverters(authenticationConverters -> authenticationConverters.add(0, preValidateTokenRequestConverter))
                        .accessTokenResponseHandler(customAuthenticationSuccessHandler)
                        .errorResponseHandler(customAuthenticationFailureHandler)
                ).tokenIntrospectionEndpoint(introspection -> introspection
                        .introspectionResponseHandler(customIntrospectionSuccessHandler)
                        .errorResponseHandler(customAuthenticationFailureHandler)
                ).tokenRevocationEndpoint(revocation -> revocation
                        .revocationResponseHandler(customRevocationSuccessHandler)
                        .errorResponseHandler(customAuthenticationFailureHandler)
                );

        http
                .cors(c -> c.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.ignoringRequestMatchers(asEndpoints))
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

    /** 2) 나머지 애플리케이션 체인 */
    @Bean
    @Order(2)
    SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/.well-known/**").permitAll()
                        .anyRequest().denyAll()
                );
        return http.build();
    }

    /** 3) Authorization Server 설정: issuer + 커스텀 토큰 엔드포인트 경로 */
    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(List.of("http://localhost:9000"));
        cfg.setAllowedMethods(List.of("POST","OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization","Content-Type","Origin","Accept"));
        cfg.setAllowCredentials(false);
        cfg.setMaxAge(Duration.ofHours(1));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/oauth2/token", cfg);
        return source;
    }

    @Bean
    FilterRegistrationBean<TokenBodyDecryptFilter> TokenBodyDecryptFilter(TokenBodyDecryptFilter f) {
        FilterRegistrationBean<TokenBodyDecryptFilter> reg = new FilterRegistrationBean<>(f);
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return reg;
    }
}
