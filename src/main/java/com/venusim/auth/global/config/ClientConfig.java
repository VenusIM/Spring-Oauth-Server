package com.venusim.auth.global.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Configuration
public class ClientConfig {

    @Value("${auth.clients.textbook.id}")
    private String textbookId;
    @Value("${auth.clients.textbook.secret}")
    private String textbookSecret;
    @Value("${auth.clients.textbook.scopes}")
    private String textbookScopes;

    @Value("${auth.clients.bookstore.id}")
    private String bookstoreId;
    @Value("${auth.clients.bookstore.secret}")
    private String bookstoreSecret;
    @Value("${auth.clients.bookstore.scopes}")
    private String bookstoreScopes;

    @Value("${auth.clients.curriculum.id}")
    private String curriculumId;
    @Value("${auth.clients.curriculum.secret}")
    private String curriculumSecret;
    @Value("${auth.clients.curriculum.scopes}")
    private String curriculumScopes;

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(PasswordEncoder pe) {
        TokenSettings token10m = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(10))
                .build();

        ClientSettings noConsent = ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .build();

        RegisteredClient textbook = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(textbookId)
                .clientSecret(pe.encode(textbookSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(sc -> sc.addAll(Arrays.asList(textbookScopes.split(","))))
                .tokenSettings(token10m)
                .clientSettings(noConsent)
                .build();

        RegisteredClient bookstore = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(bookstoreId)
                .clientSecret(pe.encode(bookstoreSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(sc -> sc.addAll(Arrays.asList(bookstoreScopes.split(","))))
                .tokenSettings(token10m)
                .clientSettings(noConsent)
                .build();

        RegisteredClient curriculum = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(curriculumId)
                .clientSecret(pe.encode(curriculumSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(sc -> sc.addAll(Arrays.asList(curriculumScopes.split(","))))
                .tokenSettings(token10m)
                .clientSettings(noConsent)
                .build();

        return new InMemoryRegisteredClientRepository(List.of(textbook, bookstore, curriculum));
    }
}
