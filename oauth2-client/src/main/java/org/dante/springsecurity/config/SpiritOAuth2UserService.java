package org.dante.springsecurity.config;

import cn.hutool.core.map.MapUtil;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.text.ParseException;
import java.util.*;

/**
 * 自定义的 OAuth2UserService — 用于在纯 OAuth2 授权模式中构建一个 OAuth2User
 * Spring Security 的 DefaultOAuth2UserService 默认用于 OpenID Connect (OIDC) 或 具有用户信息端点的 OAuth2 提供者，
 * 它期望 user-info-uri 被设置（从该地址拉取用户详细信息）。但只是使用 OAuth2 授权码模式，没有配置 OIDC，也没有 user-info-uri。
 * 解决方案: 改为使用 JWT 的 Principal 提取方式（推荐，纯 OAuth2）
 */
@Slf4j
@Service
public class SpiritOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final WebClient webClient;

    public SpiritOAuth2UserService(@Lazy WebClient webClient) {
        this.webClient = webClient;
    }

    private final static String NAME_ATTRIBUTE_KEY = "name";
    private final static String REGISTRATION_ID = "registrationId";

    // TODO: 目前只支持 JWT，后续考虑支持不同类型 token（opaque、JWT 混合场景）
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("=========> 自定义的 OAuth2UserService registrationId -> {}", registrationId);
        return switch (registrationId) {
            case "github" -> handleGithubToken(userRequest);
            case "gitee" -> handleGiteeToken(userRequest);
            case "wechat" -> null;
            default -> handleSpiritToken(userRequest);
        };
    }

    /**
     * 处理本地授权服务器 Token
     */
    private OAuth2User handleSpiritToken(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        return handleSpiritAccessToken(userRequest);
    }

    private DefaultOAuth2User handleSpiritAccessToken(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Map<String, Object> claims;
        String tokenValue = userRequest.getAccessToken().getTokenValue();
        try {
            SignedJWT signedJWT = (SignedJWT) JWTParser.parse(tokenValue);
            claims = new HashMap<>(signedJWT.getJWTClaimsSet().getClaims());
            claims.put(REGISTRATION_ID, userRequest.getClientRegistration().getRegistrationId());
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

    /**
     * 处理 Github Token
     */
    private OAuth2User handleGithubToken(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        var userInfoEndpoint = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint();
        String userInfoUri = userInfoEndpoint.getUri();
        Map<String, Object> userAttrs = webClient.get()
                .uri(userInfoUri)
                .headers(h -> h.setBearerAuth(userRequest.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();
        Map<String, Object> claims = MapUtil.isNotEmpty(userAttrs) ? new HashMap<>(userAttrs) : new HashMap<>();
        claims.put(REGISTRATION_ID, userRequest.getClientRegistration().getRegistrationId());
        claims.put(NAME_ATTRIBUTE_KEY, claims.get(userInfoEndpoint.getUserNameAttributeName()));
        Collection<SimpleGrantedAuthority> scopes = new ArrayList<>();
        return new DefaultOAuth2User(scopes, claims, NAME_ATTRIBUTE_KEY);
    }

    /**
     * 处理 Gitee Token
     */
    private OAuth2User handleGiteeToken(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        var userInfoEndpoint = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint();
        String userInfoUri = userInfoEndpoint.getUri();
        Map<String, Object> userAttrs = webClient.get()
                .uri(userInfoUri)
                .headers(h -> h.setBearerAuth(userRequest.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();
        Map<String, Object> claims = MapUtil.isNotEmpty(userAttrs) ? new HashMap<>(userAttrs) : new HashMap<>();
        claims.put(REGISTRATION_ID, userRequest.getClientRegistration().getRegistrationId());
        claims.put(NAME_ATTRIBUTE_KEY, claims.get(userInfoEndpoint.getUserNameAttributeName()));
        Collection<SimpleGrantedAuthority> scopes = new ArrayList<>();
        return new DefaultOAuth2User(scopes, claims, NAME_ATTRIBUTE_KEY);
    }

}
