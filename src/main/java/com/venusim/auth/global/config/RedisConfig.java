package com.venusim.auth.global.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.data.redis.connection.*;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    @Value("${spring.data.redis.host}") private String host;
    @Value("${spring.data.redis.port}") private int port;
    @Value("${spring.data.redis.password:}") private String password;

    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        var cfg = new RedisStandaloneConfiguration(host, port);
        if (!password.isBlank()) cfg.setPassword(RedisPassword.of(password));
        return new LettuceConnectionFactory(cfg);
    }

    // JSON 직렬화/역직렬화용 (저장/로드에 사용)
    @Bean
    public ObjectMapper redisJsonMapper() {
        var om = new ObjectMapper();
        om.registerModule(new JavaTimeModule()); // Instant 처리
        return om;
    }

    // 문자열 전용 템플릿 (키/값 모두 String)
    @Bean("indexTemplate")
    public RedisTemplate<String, String> indexTemplate(LettuceConnectionFactory cf) {
        var t = new RedisTemplate<String, String>();
        t.setConnectionFactory(cf);
        var s = new StringRedisSerializer();
        t.setKeySerializer(s);
        t.setValueSerializer(s);
        t.setHashKeySerializer(s);
        t.setHashValueSerializer(s);
        t.afterPropertiesSet();
        return t;
    }
}
