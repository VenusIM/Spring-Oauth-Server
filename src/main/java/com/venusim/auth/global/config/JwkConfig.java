package com.venusim.auth.global.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * 발급 시: active-alias의 개인키로 RS256 서명, 헤더 alg=RS256, kid=<JWK 썸프린트>.
 * JWKS: /oauth2/jwks 에 공개키(n,e)만 노출(x5c 없음).
 * 검증자는 kid로 맞는 JWK를 선택해 n,e 로 서명 검증합니다.
 * 키 회전: keystore에 새 alias 추가 → aliases 에 추가 → 배포 → active-alias 만 새 alias로 변경.
 * 이전 토큰은 기존 kid에 매칭되는 공개키로 계속 검증됩니다.
 */

@Configuration
public class JwkConfig {

    @Value("${app.access-token-minutes:10}")
    long accessMinutes;

    @Value("${app.refresh-token-days:14}")
    long refreshDays;

    @Value("${app.jwt.keystore.location}")
    Resource keystoreLocation;

    @Value("${app.jwt.keystore.type:PKCS12}")
    String keystoreType;

    @Value("${app.jwt.keystore.storepass}")
    String storePass;

    @Value("${app.jwt.keystore.keypass}")
    String keyPass;

    @Value("${app.jwt.keystore.active-alias}")
    String activeAlias;

    // 회전 대비: 여러 alias를 동시에 JWKS에 올릴 수 있음(콤마 구분)
    @Value("#{'${app.jwt.keystore.aliases:${app.jwt.keystore.aliases}}'.split(',')}")
    List<String> aliases;

    private static final String CUSTOM_CLAIM = "memid";

    /** Keystore → (여러) RSA JWK 생성 (x5c 미포함) */
    @Bean
    JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyStore ks = KeyStore.getInstance(keystoreType);
        try (InputStream is = keystoreLocation.getInputStream()) {
            ks.load(is, storePass.toCharArray());
        }

        if (aliases == null || aliases.isEmpty()) {
            aliases = List.of(activeAlias);
        }

        List<JWK> jwks = new ArrayList<>();
        for (String alias : aliases.stream().map(String::trim).filter(s -> !s.isEmpty()).toList()) {
            if (!ks.isKeyEntry(alias)) continue;

            PrivateKeyEntry entry = (PrivateKeyEntry) ks.getEntry(alias, new PasswordProtection(keyPass.toCharArray()));
            if (entry == null) continue;

            PrivateKey privKey = entry.getPrivateKey();
            Certificate cert = entry.getCertificate();
            if (!(privKey instanceof RSAPrivateKey priv) || !(cert.getPublicKey() instanceof RSAPublicKey pub)) continue;

            // 1) 우선 kid 없이 RSA JWK 생성
            RSAKey base = new RSAKey.Builder(pub)
                    .privateKey(priv)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();

            // 2) RFC 7638 JWK Thumbprint로 kid 생성(인증서 만료 영향 無)
            Base64URL thumb = base.toPublicJWK().computeThumbprint(); // SHA-256 default
            String kid = thumb.toString();

            // 3) 최종 JWK (x5c 미포함)
            RSAKey rsaJwk = new RSAKey.Builder(pub)
                    .privateKey(priv)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(kid)
                    .build();

            jwks.add(rsaJwk);
        }

        if (jwks.isEmpty()) {
            throw new IllegalStateException("Keystore에 유효한 RSA 개인키(alias=" + aliases + ")가 없습니다.");
        }

        // JWKS 엔드포인트에서 공개키가 노출됨(개인키는 비공개)
        JWKSet jwkSet = new JWKSet(jwks);
        return (selector, ctx) -> selector.select(jwkSet);
    }

    /** 토큰 TTL 등 */
    @Bean
    TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(accessMinutes))
                .refreshTokenTimeToLive(Duration.ofDays(refreshDays))
                .reuseRefreshTokens(false)
                .build();
    }

    /** JWT 생성기 */
    @Bean
    OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource,
                                           OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(encoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);

        OAuth2AccessTokenGenerator access = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refresh = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(jwtGenerator, access, refresh);
    }

    /** alg=RS256, kid 자동 설정, 커스텀 클레임 추가 */
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return ctx -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(ctx.getTokenType())) return;

            // 비대칭키 RS256
            ctx.getJwsHeader().algorithm(SignatureAlgorithm.RS256);

            // 활성 alias의 kid를 헤더에 지정(검증자 키 선택 명확화)
            try {
                String activeKid = resolveKidFromActiveAlias();
                ctx.getJwsHeader().keyId(activeKid);
            } catch (Exception e) {
                throw new IllegalStateException("active-alias의 kid 계산 실패", e);
            }

            var grant = ctx.getAuthorizationGrant();
            if (grant instanceof OAuth2AuthorizationGrantAuthenticationToken g) {
                Object memid = g.getAdditionalParameters().get(CUSTOM_CLAIM);
                if (memid instanceof String s && !s.isBlank()) {
                    ctx.getClaims().claim(CUSTOM_CLAIM, s);
                }
            }
        };
    }

    /** active-alias로부터 JWK thumbprint kid 계산 */
    private String resolveKidFromActiveAlias() throws Exception {
        KeyStore ks = KeyStore.getInstance(keystoreType);
        try (InputStream is = keystoreLocation.getInputStream()) {
            ks.load(is, storePass.toCharArray());
        }
        if (!ks.isKeyEntry(activeAlias)) {
            throw new IllegalStateException("active-alias가 keystore에 없습니다: " + activeAlias);
        }
        PrivateKeyEntry entry = (PrivateKeyEntry) ks.getEntry(activeAlias, new PasswordProtection(keyPass.toCharArray()));
        PrivateKey privKey = entry.getPrivateKey();
        Certificate cert = entry.getCertificate();
        if (!(privKey instanceof RSAPrivateKey priv) || !(cert.getPublicKey() instanceof RSAPublicKey pub)) {
            throw new IllegalStateException("active-alias가 RSA 키가 아닙니다: " + activeAlias);
        }

        RSAKey base = new RSAKey.Builder(pub)
                .privateKey(priv)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();

        return base.toPublicJWK().computeThumbprint().toString();
    }
}
