package com.venusim.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.venusim.auth.domain.member.MemberService;
import com.venusim.auth.domain.member.MemberSsoRandomRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ActiveProfiles("local")
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    MemberService memberService;

    @Autowired
    MemberSsoRandomRepository repository;

    @Autowired
    MemberSsoRandomRepository memberSsoRandomRepository;

    private static final String TOKEN_URI = "/oauth2/token";
    private static final String SCOPE = "read";
    private static final String HMAC_SECRET = "supersecrettestkeywhichislongenough";
    private static final String encodedHeader = "Basic v1TBP9fJ8397To/PCVGKCo5lpWGvkL8Hh+o8Hj5IlyY=";

    /* =========================
     * 인증/요청 유효성 테스트
     * ========================= */
    @Nested
    @DisplayName("요청 유효성")
    class RequestValidation {

        @Test
        void contextBeans() {
            assertThat(memberService).isNotNull();
            assertThat(repository).isNotNull();
            assertThat(memberSsoRandomRepository).isNotNull();
        }

        @Test
        @DisplayName("Authorization 헤더 없음 → 401")
        void whenNoAuthorization_then401() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZAhW+++7XejMNQQiBm2jk4ts8f2ofZmV+ZTBVWLlPk1qNGlNboP52J5DIybJyjXBbuwR7BGkuozxlFmdVJPqME="))
                    .andExpect(status().isUnauthorized())
                    .andDo(print());
        }

        @Test
        @DisplayName("Basic 자격증명 Base64 형식 오류 → 400")
        void whenMalformedBasic_then401() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, "Basic not-base64@@")
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZAhW+++7XejMNQQiBm2jk4ts8f2ofZmV+ZTBVWLlPk1qNGlNboP52J5DIybJyjXBbuwR7BGkuozxlFmdVJPqME="))
                    .andExpect(status().isBadRequest())
                    .andDo(print());
        }

        @Test
        @DisplayName("clientId 불일치 → 401")
        void whenWrongClientId_then401() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            // textbooks:textbook-secret
                            .header(HttpHeaders.AUTHORIZATION, "Basic ZEQxuaqMPlfAii/4OTqRDhLF3sSyUdweIoAYA7mlk+8=")
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZAhW+++7XejMNQQiBm2jk4ts8f2ofZmV+ZTBVWLlPk1qNGlNboP52J5DIybJyjXBbuwR7BGkuozxlFmdVJPqME="))
                    .andExpect(status().isUnauthorized())
                    .andDo(print());
        }

        @Test
        @DisplayName("clientSecret 불일치 → 401")
        void whenWrongSecret_then401() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            // textbook:textbooks-secret
                            .header(HttpHeaders.AUTHORIZATION, "Basic v1TBP9fJ8397To/PCVGKCq8X0ttM8+CjSaDhJ+H63Kw=")
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZAhW+++7XejMNQQiBm2jk4ts8f2ofZmV+ZTBVWLlPk1qNGlNboP52J5DIybJyjXBbuwR7BGkuozxlFmdVJPqME="))
                    .andExpect(status().isUnauthorized())
                    .andDo(print());
        }

        @Test
        @DisplayName("grant_type 누락 → 400 invalid_request")
        void whenMissingGrantType_then400() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, encodedHeader)
                            // memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=unknown
                            .content("jwt=YoR4Ox/SOIDvD0vbnDPZNPhFcH4r1H8azRqeVwQMSiD6HXDt3BCH2gdy8YzHnyho"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("invalid_request"))
                    .andDo(print());
        }

        @Test
        @DisplayName("지원하지 않는 grant_type → 400 unsupported_grant_type")
        void whenUnsupportedGrant_then400() throws Exception {

            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, encodedHeader)
                            // grant_type=credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5
                            .content("jwt=ldHrP9V1fB8zGu9l9EzSZ7wTfY4DCSA/HadoY0vUNoIR2Dkr3g25tGOlxa/ok4US+ssxH8HiZ1TyRwDR6D/D0A=="))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("unsupported_grant_type"))
                    .andDo(print());
        }

        /*@Test
        @DisplayName("scope 누락 → 400 invalid_request (정책에 따라 invalid_scope 가능)")
        void whenMissingScope_then400() throws Exception {
            when(userService.isValidUser("group1_t")).thenReturn(true);
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                            .content("jwt=grant_type=client_credentials&userId=group1_t"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("invalid_scope"));
        }*/

        /*@Test
        @DisplayName("허용되지 않은 scope → 400 invalid_scope")
        void whenInvalidScope_then400() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, encodedHeader)
                            // grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=unknown
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZAhW+++7XejMNQQiBm2jk4ts8f2ofZmV+ZTBVWLlPk1qNGlNboP52J5DIybJyjXBa/G3t7my6VGhfa5Im3SHKXB9Pdl72x1tc7GFN/zVVtg"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("invalid_scope"))
                    .andDo(print());
        }*/
    }

    /* =========================
     * 사용자 파라미터(userId) 검증
     * ========================= */
    @Nested
    @DisplayName("userId 검증")
    class UserIdValidation {

/*        @Test
        @DisplayName("userId 무효 → 401 user_not_found")
        void whenUserInvalid_then401() throws Exception {
            when(userService.isValidUser("bad-tenant")).thenReturn(false);

            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, basic(CLIENT_ID, CLIENT_SECRET))
                            .content("jwt=grant_type=client_credentials&scope=" + SCOPE + "&userId=bad-tenant"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("user_not_found"))
                    .andExpect(jsonPath("$.description").value("Unknown user : bad-tenant"))
                    .andDo(print());
        }*/

        @Test
        @DisplayName("userId 미제공(옵션일 때) & 클레임 부재")
        void whenUserMissing_then200AndNoClaim() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, encodedHeader)
                            // grant_type=client_credentials&tmpkey=3b1de29ea9ccdad5
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZrRy0AQ7T3DXZAgla4VjWgLnCPxwvT60JaTYRIxeig9afi7kEQC0SEBsXkmf62rkw=="))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("invalid_request"))
                    .andExpect(jsonPath("$.description").value("Missing or invalid parameter: memid"))
                    .andDo(print());
        }

        @Test
        @DisplayName("userId 유효 → 200 & access_token 클레임 포함")
        void whenUserValid_thenClaimPresent() throws Exception {

            MvcResult res = mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, encodedHeader)
                            // grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZAhW+++7XejMNQQiBm2jk4ts8f2ofZmV+ZTBVWLlPk1qNGlNboP52J5DIybJyjXBbuwR7BGkuozxlFmdVJPqME="))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.access_token").exists())
                    .andExpect(jsonPath("$.token_type").value("Bearer"))
                    .andDo(print())
                    .andReturn();

            JsonNode json = objectMapper.readTree(res.getResponse().getContentAsByteArray());
            String accessToken = json.get("access_token").asText();

            SignedJWT jwt = SignedJWT.parse(accessToken);
            assertThat(jwt.getJWTClaimsSet().getStringClaim("memid")).isEqualTo("wavesu");
            assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("http://localhost");
        }
    }

    /* =========================
     * 응답 형식/보안 헤더/JWT 상세
     * ========================= */
    @Nested
    @DisplayName("응답 규격 & JWT")
    class ResponseAndJwt {

        @Test
        @DisplayName("표준 응답 필드 & 보안 헤더 & JWT 서명/만료 검증")
        void responseShapeHeadersAndJwt() throws Exception {

            MvcResult res = mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, encodedHeader)
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZAhW+++7XejMNQQiBm2jk4ts8f2ofZmV+ZTBVWLlPk1qNGlNboP52J5DIybJyjXBbuwR7BGkuozxlFmdVJPqME="))
                    .andExpect(status().isOk())
                    .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                    .andExpect(header().string("Pragma", "no-cache"))
                    .andExpect(jsonPath("$.access_token").exists())
                    .andExpect(jsonPath("$.token_type").value("Bearer"))
                    .andExpect(jsonPath("$.expires_in").isNumber())
//                    .andExpect(jsonPath("$.scope").value(SCOPE))
                    .andDo(print())
                    .andReturn();

            JsonNode json = objectMapper.readTree(res.getResponse().getContentAsByteArray());
            String token = json.get("access_token").asText();

            // JWT 파싱 & 서명 검증(HMAC)
            SignedJWT jwt = SignedJWT.parse(token);
            boolean verified = jwt.verify(new MACVerifier(HMAC_SECRET));
            assertThat(verified).isTrue();

            /*// 만료시간 ≈ 5분 확인 (허용 오차 10초)
            Date iat = jwt.getJWTClaimsSet().getIssueTime();
            Date exp = jwt.getJWTClaimsSet().getExpirationTime();
            long seconds = (exp.getTime() - iat.getTime()) / 1000;
            assertThat(seconds).isBetween(290L, 310L); // 5분 ±10초

            // nb: 클럭스큐 허용(예: not-before가 있다면 현재시간과 비교)
            Instant now = Instant.now();
            assertThat(exp.toInstant()).isAfter(now);*/
        }

        @Test
        @DisplayName("Content-Type은 application/json")
        void contentTypeIsJson() throws Exception {

            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .header(HttpHeaders.AUTHORIZATION, encodedHeader)
                            .content("jwt=5Rz4nzWFTMTEpqN+BL2n+ZAhW+++7XejMNQQiBm2jk4ts8f2ofZmV+ZTBVWLlPk1qNGlNboP52J5DIybJyjXBbuwR7BGkuozxlFmdVJPqME="))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andDo(print());
        }
    }
}
