package com.venusim.auth.domain;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static String kAtk(String token) { return "atk:" + token; }
    private static String kAid(String aid)   { return "aid:" + aid; }

    private final RedisTemplate<String, String> redis;
    private final RegisteredClientRepository clients;
    private final ObjectMapper json;

    public RedisOAuth2AuthorizationService(
            @Qualifier("indexTemplate") RedisTemplate<String, String> redis,
            RegisteredClientRepository clients,
            @Qualifier("redisJsonMapper") ObjectMapper json) {
        this.redis = redis;
        this.clients = clients;
        this.json = json;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        if (authorization == null) return;

        var access = authorization.getAccessToken();
        if (access == null) return; // client_credentials 전용이라 access만 다룸

        var at = access.getToken();
        String token = at.getTokenValue();
        String authId = authorization.getId();

        boolean invalidated = access.isInvalidated();
        Instant now = Instant.now();
        Instant exp  = Optional.ofNullable(at.getExpiresAt()).orElse(now.plusSeconds(1));
        boolean expired = !exp.isAfter(now);

        if (invalidated || expired) {
            redis.delete(kAtk(token));
            redis.delete(kAid(authId));
            return;
        }

        Duration ttl = Duration.between(now, exp);
        if (ttl.isNegative() || ttl.isZero()) ttl = Duration.ofSeconds(1);

        var rec = new TokenRecord(
                authId,
                authorization.getRegisteredClientId(),
                authorization.getPrincipalName(),
                authorization.getAuthorizedScopes(),
                Optional.ofNullable(at.getIssuedAt()).orElse(now),
                exp,
                authId, // jti 대용(원하면 claims의 jti 사용)
                true
        );

        try {
            String jsonStr = json.writeValueAsString(rec);
            redis.opsForValue().set(kAtk(token), jsonStr, ttl);
            redis.opsForValue().set(kAid(authId), token, ttl);
            // log.info("saved/updated: SET {} (ttl={}s), SET {}", kAtk(token), ttl.toSeconds(), kAid(authId));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to write token record to Redis", e);
        }
    }


    @Override
    public void remove(OAuth2Authorization authorization) {
        if (authorization == null) return;
        var access = authorization.getAccessToken();
        if (access != null) {
            String token = access.getToken().getTokenValue();
            redis.delete(kAtk(token));
        }
        redis.delete(kAid(authorization.getId()));
    }

    @Override
    public OAuth2Authorization findById(String id) {
        String token = redis.opsForValue().get(kAid(id));
        if (token == null) return null;
        return findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (token == null) return null;
        if (tokenType != null && !OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) return null;

        String jsonStr = redis.opsForValue().get(kAtk(token));
        if (jsonStr == null) return null;

        TokenRecord rec;
        try {
            rec = json.readValue(jsonStr, new TypeReference<>() {});
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse token record JSON", e);
        }

        if (!rec.active() || rec.expiresAt().isBefore(Instant.now())) return null;

        RegisteredClient rc =
                Optional.ofNullable(clients.findById(rec.clientId()))
                        .orElseGet(() -> clients.findByClientId(rec.clientId()));

        if (rc == null) return null;

        var access = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                token,
                rec.issuedAt(),
                rec.expiresAt(),
                rec.scopes()
        );

        // 메타/클레임 최소 구성 (필요 시 확장)
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub",  rec.principal());
        claims.put("aud",  List.of(rc.getClientId()));
        claims.put("iat",  rec.issuedAt());
        claims.put("exp",  rec.expiresAt());
        claims.put("jti",  rec.jti());

        return OAuth2Authorization.withRegisteredClient(rc)
                .id(rec.authId())
                .principalName(rec.principal())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(rec.scopes())
                .token(access, md -> md.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims))
                .build();
    }
}
