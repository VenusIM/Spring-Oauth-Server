package com.venusim.auth.global.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.*;

public class ParamOverrideRequest extends HttpServletRequestWrapper {
    private final Map<String, String[]> params;

    // 선택적 Authorization 헤더 오버라이드 값
    private final String authorizationOverride;

    public ParamOverrideRequest(HttpServletRequest request,
                                Map<String, String[]> newParams,
                                String authorizationOverride) {
        super(request);
        this.params = Collections.unmodifiableMap(new LinkedHashMap<>(newParams));
        // 헤더 인젝션 방지: CR/LF 제거
        if (authorizationOverride != null) {
            this.authorizationOverride = authorizationOverride.replaceAll("[\\r\\n]", "");
        } else {
            this.authorizationOverride = null;
        }
    }

    // ----------------- parameters -----------------
    @Override
    public String getParameter(String name) {
        String[] values = params.get(name);
        return (values != null && values.length > 0) ? values[0] : null;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return params;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(params.keySet());
    }

    @Override
    public String[] getParameterValues(String name) {
        return params.get(name);
    }

    // ----------------- headers -----------------
    @Override
    public String getHeader(String name) {
        if (authorizationOverride != null && "authorization".equalsIgnoreCase(name)) {
            return authorizationOverride;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (authorizationOverride != null && "authorization".equalsIgnoreCase(name)) {
            return Collections.enumeration(Collections.singletonList(authorizationOverride));
        }
        return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        // 원본 + (필요 시) Authorization 이름 포함
        Set<String> names = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Enumeration<String> e = super.getHeaderNames();
        while (e.hasMoreElements()) names.add(e.nextElement());
        if (authorizationOverride != null) names.add("Authorization");
        return Collections.enumeration(names);
    }
}
