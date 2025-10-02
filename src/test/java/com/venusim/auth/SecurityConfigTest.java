package com.venusim.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.venusim.auth.domain.member.MemberService;
import com.venusim.auth.domain.member.MemberSsoRandomRepository;
import com.venusim.auth.global.util.AuthUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles("local")
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    MemberService memberService;

    @Autowired
    MemberSsoRandomRepository repository;

    @Autowired
    MemberSsoRandomRepository memberSsoRandomRepository;

    @Autowired
    AuthUtil authUtil;

    private static final String TOKEN_URI = "/oauth2/token";
    private static final String INTROSPECT_URI = "/oauth2/introspect";
    private static final String REVOKE_URI = "/oauth2/revoke";

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
                            .contentType(MediaType.TEXT_PLAIN)
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=read")))
                    .andExpect(status().isUnauthorized())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_client\",\"description\":\"Missing or invalid header: Authorization\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("Basic 자격 증명 형식 오류 → 400")
        void whenMalformedNonBasic_then400() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .header(HttpHeaders.AUTHORIZATION, "Basic " + authUtil.encryptBase64("not-base64@@"))
                            .contentType(MediaType.TEXT_PLAIN)
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=read")))
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_request\",\"description\":\"Invalid Authorization header format. Missing client_id and/or client_secret.\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("Basic Base64 non encode → 400")
        void whenMalformedNonEncodeBasic_then400() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic not-base64@@")
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=read")))
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_request\",\"description\":\"Invalid Authorization header format. Failed to decode credentials.\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("Basic 자격증명 Base64 형식 오류 → 400")
        void whenMalformedBasic_then400() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("not-base64@@"))
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=read")))
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_request\",\"description\":\"Invalid Authorization header format. Missing client_id and/or client_secret.\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("clientId 불일치 → 401")
        void whenWrongClientId_then401() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbooks:textbook-secret"))
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=read")))
                    .andExpect(status().isUnauthorized())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_client\",\"description\":\"Client authentication failed: client_id\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("clientSecret 불일치 → 401")
        void whenWrongSecret_then401() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbooks-secret"))
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=read")))
                    .andExpect(status().isUnauthorized())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_client\",\"description\":\"Client authentication failed: client_secret\"}")))
                    .andDo(print())
                    .andReturn();
        }

        @Test
        @DisplayName("grant_type 누락 → 400 invalid_request")
        void whenMissingGrantType_then400() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("memid=wavesu&tmpkey=3b1de29ea9ccdad5&scope=unknown")))
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_request\",\"description\":\"Missing or invalid parameter: grant_type\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("지원하지 않는 grant_type → 400 unsupported_grant_type")
        void whenUnsupportedGrant_then400() throws Exception {

            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            //
                            .content(authUtil.encryptBase64("grant_type=credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5")))
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"unsupported_grant_type\",\"description\":\"Unsupported grant_type: credentials\"}")))
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

        @Test
        @DisplayName("userId 무효 → 401 user_not_allowed")
        void whenUserInvalid_then401() throws Exception {

            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=bad-tenant&tmpkey=3b1de29ea9ccdad5")))
                    .andExpect(status().isUnauthorized())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"user_not_allowed\",\"description\":\"User is not allowed to obtain a token.\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("userId 미제공 & 클레임 부재")
        void whenUserMissing_then401AndNoClaim() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("grant_type=client_credentials&tmpkey=3b1de29ea9ccdad5")))
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_request\",\"description\":\"Missing or invalid parameter: memid\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("tmpkey 미제공 & 클레임 부재")
        void whenTmpKeyMissing_then401AndNoClaim() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu")))
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_request\",\"description\":\"Missing or invalid parameter: tmpkey\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("정상 로그인")
        void success() throws Exception {
            mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5")))
                    .andExpect(status().isOk())
                    .andDo(print());
        }
    }

    @Nested
    @DisplayName("토큰 검증 instropection")
    class TokenValidation {
        @Test
        @DisplayName("정상 처리")
        void success() throws Exception{

            MvcResult mvcResult = mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5")))
                    .andReturn();

            String b64 = mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8);
            String json = authUtil.decryptBase64(b64);
            Map<String, Object> payload = new ObjectMapper().readValue(json, new TypeReference<>() {});

            mockMvc.perform(post("/oauth2/introspect")
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("token="+payload.get("access_token")+"&token_type_hint=access_token")))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("token 누락 -> 400")
        void tokenFail_400() throws Exception{

            mockMvc.perform(post("/oauth2/introspect")
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("token_type_hint=access_token")))
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_request\",\"description\":\"Missing or invalid parameter: token\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("미인증 토큰 -> 401")
        void tokenValidFail_401() throws Exception{
            mockMvc.perform(post("/oauth2/introspect")
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, "Basic "+authUtil.encryptBase64("textbook:textbook-secret"))
                            .content(authUtil.encryptBase64("token=abc&token_type_hint=access_token")))
                    .andExpect(status().isUnauthorized())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_token\",\"description\":\"Token is inactive or expired.\"}")))
                    .andDo(print());
        }
    }

    @Nested
    @DisplayName("토큰 파기 revoke")
    class TokenRevoke {

        private static final String CLIENT_ID = "textbook";
        private static final String CLIENT_SECRET = "textbook-secret";

        private String basicEnc() {
            return "Basic " + authUtil.encryptBase64(CLIENT_ID + ":" + CLIENT_SECRET);
        }
        private String enc(String plain) { return authUtil.encryptBase64(plain); }

        private Map<String, Object> decryptJson(MvcResult r) throws Exception {
            String b64 = r.getResponse().getContentAsString(StandardCharsets.UTF_8);
            String json = authUtil.decryptBase64(b64);
            return new ObjectMapper().readValue(json, new TypeReference<>() {});
        }

        private String issueAccessToken() throws Exception {
            MvcResult res = mockMvc.perform(post(TOKEN_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, basicEnc())
                            .content(enc("grant_type=client_credentials&memid=wavesu&tmpkey=3b1de29ea9ccdad5")))
                    .andExpect(status().isOk())
                    .andReturn();
            Map<String, Object> payload = decryptJson(res);
            return String.valueOf(payload.get("access_token"));
        }

        /* ---------- Tests ---------- */

        @Test
        @DisplayName("정상 폐기 → 200, 이후 introspect 401 invalid_token")
        void revoke_success_then_introspect_unauthorized() throws Exception {
            String accessToken = issueAccessToken();

            mockMvc.perform(post(REVOKE_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, basicEnc())
                            .content(enc("token=" + accessToken + "&token_type_hint=access_token")))
                    .andExpect(status().isOk());

            // 3) revoke된 토큰 introspect → 401 invalid_token (커스텀 핸들러 정책)
            mockMvc.perform(post(INTROSPECT_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, basicEnc())
                            .content(enc("token=" + accessToken)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_token\",\"description\":\"Token is inactive or expired.\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("token 파라미터 누락 → 400 invalid_request")
        void revoke_missing_token_bad_request() throws Exception {
            mockMvc.perform(post(REVOKE_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, basicEnc())
                            .content(enc("token_type_hint=access_token"))) // token 누락
                    .andExpect(status().isBadRequest())
                    .andExpect(result -> assertThat(result.getResponse().getContentAsString()).isEqualTo(authUtil.encryptBase64("{\"error\":\"invalid_request\",\"description\":\"Missing or invalid parameter: token\"}")))
                    .andDo(print());
        }

        @Test
        @DisplayName("같은 토큰 2회 폐기(Idempotent) → 두 번 모두 200")
        void revoke_twice_idempotent() throws Exception {
            String accessToken = issueAccessToken();

            // 1차 폐기
            mockMvc.perform(post(REVOKE_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, basicEnc())
                            .content(enc("token=" + accessToken + "&token_type_hint=access_token")))
                    .andExpect(status().isOk());

            // 2차 동일 토큰 폐기 → 그래도 200 (RFC 7009 권장)
            mockMvc.perform(post(REVOKE_URI)
                            .contentType(MediaType.TEXT_PLAIN)
                            .header(HttpHeaders.AUTHORIZATION, basicEnc())
                            .content(enc("token=" + accessToken + "&token_type_hint=access_token")))
                    .andExpect(status().isOk());
        }
    }
}
