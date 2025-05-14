package org.dante.springsecurity.config;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.*;

/**
 * 自定义的 OAuth2UserService — 用于在纯 OAuth2 授权模式中构建一个 OAuth2User
 * Spring Security 的 DefaultOAuth2UserService 默认用于 OpenID Connect (OIDC) 或 具有用户信息端点的 OAuth2 提供者，
 * 它期望 user-info-uri 被设置（从该地址拉取用户详细信息）。但只是使用 OAuth2 授权码模式，没有配置 OIDC，也没有 user-info-uri。
 * 解决方案: 改为使用 JWT 的 Principal 提取方式（推荐，纯 OAuth2）
 */
@Service
public class SpiritOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final static String NAME_ATTRIBUTE_KEY = "name";

    // TODO: 目前只支持 JWT，后续考虑支持不同类型 token（opaque、JWT 混合场景）
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String tokenValue = userRequest.getAccessToken().getTokenValue();
        Map<String, Object> claims;

        try {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(tokenValue);
            claims = new HashMap<>(signedJWT.getJWTClaimsSet().getClaims());
        } catch (ParseException e) {
            throw new IllegalArgumentException("无法解析JWT", e);
        }

        // 提取权限
        Collection<SimpleGrantedAuthority> scopes = new ArrayList<>();
        Object scope = claims.get("scope");
        if (scope instanceof List<?>) {
            ((List<?>) scope).forEach(auth -> scopes.add(new SimpleGrantedAuthority(auth.toString())));
        }

        // 提取用户名
        String name = (String) claims.getOrDefault("sub", "unknown");
        claims.put(NAME_ATTRIBUTE_KEY, name);

        return new DefaultOAuth2User(scopes, claims, NAME_ATTRIBUTE_KEY);
    }
}
