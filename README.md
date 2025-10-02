# JWT PROTOCOL (요약)

JWT 기반 인증 서버의 주요 프로토콜 정의 및 에러 응답 정리 문서입니다.\
모든 요청/응답 본문은 **KISA SEED CBC 암호화 후 Base64**로
전송(`CBC_ENC`) / 수신 시 복호화(`CBC_DEC`)합니다.

------------------------------------------------------------------------

## 📑 목차

1.  [로그인 (Token 발급)](#1-로그인-token-발급)
2.  [토큰 검증 (Introspect / JWKS)](#2-토큰-검증-introspect--jwks)
3.  [재발행 요청 (Reissue)](#3-재발행-요청-reissue)
4.  [로그아웃 / 토큰 폐기 (Revoke)](#4-로그아웃--토큰-폐기-revoke)
5.  [공통 인증 헤더 에러](#5-공통-인증-헤더-에러)

------------------------------------------------------------------------

## 1) 로그인 (Token 발급)

-   **POST** `/oauth2/token`

-   **Body 예시**

        CBC_ENC(grant_type=client_credentials[&scope=read]&memid=<회원아이디>&tmpkey=<임시발급키>)

-   **성공 응답**

``` json
CBC_DEC({
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 599
})
```

-   **에러**

``` json
// grant_type 누락 → 400
{"error":"invalid_client","description":"Missing or invalid parameter: grant_type"}
// 잘못된 grant_type → 400
{"error":"unsupported_grant_type","description":"Unsupported grant_type: credentials"}
// memid/tmpkey 누락 → 400
{"error":"invalid_request","description":"Missing or invalid parameter: {특정키}"}
// 값 불일치/만료 → 401
{"error":"user_not_allowed","description":"User is not allowed to obtain a token."}
```

------------------------------------------------------------------------

## 2) 토큰 검증 (Introspect / JWKS)

-   **POST** `/oauth2/introspect`

    -   Body:

            CBC_ENC(token={access_token}[&token_type_hint=access_token])

-   **JWKS**: `/oauth2/jwks`\
    (서버 검증 위임 / public key로 직접 검증 가능)

-   **성공 응답**

``` json
200 OK
{"active":true,"sub":"textbook","aud":["textbook"],"token_type":"Bearer","client_id":"textbook", ...}
```

-   **에러**

``` json
// token 누락 → 400
{"error":"invalid_request","description":"Missing or invalid parameter: token"}
// 비활성/만료 토큰 → 401
{"error":"invalid_token","description":"Token is inactive or expired."}
```

------------------------------------------------------------------------

## 3) 재발행 요청 (Reissue)

-   **POST** `/oauth2/token`

-   **Body 예시**

        CBC_ENC(grant_type=client_credentials[&scope=read]&memid=<회원아이디>&tmpkey=<임시발급키>)

-   **성공 응답**

``` json
CBC_DEC({
  "access_token": "new key",
  "token_type": "Bearer",
  "expires_in": 600
})
```

-   **에러** (로그인과 동일 규칙)

``` json
{"error":"invalid_client","description":"Missing or invalid parameter: grant_type"}
{"error":"unsupported_grant_type","description":"Unsupported grant_type: credentials"}
{"error":"invalid_request","description":"Missing or invalid parameter: {특정키}"}
{"error":"user_not_allowed","description":"User is not allowed to obtain a token."}
```

------------------------------------------------------------------------

## 4) 로그아웃 / 토큰 폐기 (Revoke)

-   **POST** `/oauth2/revoke`

-   **Body 예시**

        CBC_ENC(token={access_token}[&token_type_hint=access_token])

-   **성공 응답**
    200 OK  (토큰 파기 성공 / Inactive·존재하지 않는 토큰이어도 200 – RFC 7009 준수)

-   **에러**

``` json
 // token 누락 → 400
{"error":"invalid_request","description":"Missing or invalid parameter: token"}
```

------------------------------------------------------------------------

## 5) 공통 인증 헤더 에러

``` json
// 헤더 누락 → 401
{"error":"invalid_client","description":"Missing or invalid header: Authorization"}
// Basic 포맷 오류 → 400
{"error":"invalid_request","description":"Invalid Authorization header format. Missing client_id and/or client_secret."}
// Base64 디코드 오류 → 400
{"error":"invalid_request","description":"Invalid Authorization header format. Failed to decode credentials."}
// ClientId 불일치 → 401
{"error":"invalid_client","description":"Client authentication failed: client_id"}
// ClientSecret 불일치 → 401
{"error":"invalid_client","description":"Client authentication failed: client_secret"}
```
