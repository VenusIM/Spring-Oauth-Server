package com.venusim.auth.global.util;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class AuthUtil {
    @Value("${app.seed-cbc-key}")
    private String key;

    @Value("${app.seed-cbc-iv}")
    private String iv;

    private byte[] hexKey;
    private byte[] hexIv;

    @PostConstruct
    void init() {
        hexKey = HexFormat.of().parseHex(key.replaceAll("\\s+", ""));
        hexIv = HexFormat.of().parseHex(iv.replaceAll("\\s+", ""));
    }

    public byte[] decrypt(byte[] bytes) {
        return KISA_SEED_CBC.SEED_CBC_Decrypt(hexKey, hexIv, bytes, 0, bytes.length);
    }

    public byte[] decrypt(String base64) {
        byte[] decoded = Base64.getDecoder().decode(base64);
        return decrypt(decoded);
    }

    public String decryptBase64(String base64) {
        byte[] back = decrypt(base64);
        return new String(back, StandardCharsets.UTF_8);
    }

    public String decryptBase64(byte[] bytes) {
        byte[] back = decrypt(bytes);
        return new String(back, StandardCharsets.UTF_8);
    }

    public byte[] encrypt(byte[] bytes) {
        return KISA_SEED_CBC.SEED_CBC_Encrypt(hexKey, hexIv, bytes, 0, bytes.length);
    }

    public byte[] encrypt(String plain) {
        byte[] decoded = plain.getBytes(StandardCharsets.UTF_8);
        return encrypt(decoded);
    }

    public String encryptBase64(String base64) {
        byte[] back = encrypt(base64);
        return Base64.getEncoder().encodeToString(back);
    }

    public String encryptBase64(byte[] bytes) {
        byte[] back = encrypt(bytes);
        return Base64.getEncoder().encodeToString(back);
    }

    public void encodeResponse(HttpServletResponse response, String json) throws IOException {

        String b64 = encryptBase64(json);
        System.out.println(json);
        System.out.println(b64);
        byte[] bytes = b64.getBytes(StandardCharsets.UTF_8);

        // RFC 권장 캐시 방지 헤더
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("text/plain");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
        response.flushBuffer();
    }
}
