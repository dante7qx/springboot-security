package org.dante.springsecurity.config;

import cn.hutool.core.lang.Console;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.dante.springsecurity.service.OidcUserInfoService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.util.Set;

@Configuration
public class JwtTokenConfig {

    /**
     * JWT 编码器
     * 将 JWT 的内容（Claims）和头部（Header）信息组合起来，并使用指定的加密算法进行签名，最终生成可用的 JWT 字符串
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        // 基于 Nimbus JOSE + JWT 库，自动从 JWKSource 选择合适的密钥进行签名
        NimbusJwtEncoder delegate = new NimbusJwtEncoder(jwkSource);
        return parameters -> {
            Console.log("==================> JwtEncoder.encode 被调用，参数:{} --> {}", parameters.getJwsHeader(), parameters.getClaims());
            return delegate.encode(parameters);
        };
    }

    /**
     * JWT 解码器
     * 1. 授权服务器: 仅在授权服务器内部使用 JWT（如生成访问令牌）, 不需要 JWT 解码器
     * 2. 资源服务器: 需要验证 JWT 令牌（例如访问受保护 API），必须显式配置 JwtDecoder
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 负责生成各种 OAuth 2.0 令牌（如访问令牌(Access Token)、刷新令牌(Refresh Token)、授权码(Authorization Code)）
     * <p>
     * 1. 令牌生成中枢
     * （1）统一生成 OAuth2 规范定义的所有令牌类型
     * （2）包括访问令牌(Access Token)、刷新令牌(Refresh Token)、授权码(Authorization Code)
     * 2. 可扩展的生成策略
     * （1）支持自定义令牌格式（JWT、不透明令牌等）
     * （2）允许实现特定业务逻辑的令牌生成规则
     * 3. 与认证流程集成
     * （1）被授权码模式、客户端凭证模式等所有授权流程使用
     * （2）与令牌增强器(TokenEnhancer)协同工作
     */
    @Bean
    public OAuth2TokenGenerator<?> jwtTokenGenerator(JwtEncoder jwtEncoder, OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        // 生成器会按注册顺序执行, 第一个能处理当前令牌类型的生成器将被使用
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                accessTokenGenerator,
                refreshTokenGenerator
        );
    }

    /**
     * 在 OAuth2 授权服务器生成 JWT 格式的访问令牌时，向令牌中添加自定义声明 (custom claims)
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(OidcUserInfoService userInfoService) {
        return context -> {

            String tokenType = context.getTokenType().getValue();
            Console.log("==================> OAuth2TokenCustomizer  被调用，Token 类型 {}", tokenType);

            Authentication principal = context.getPrincipal();
            Set<String> requestedScopes = context.getAuthorizedScopes();

            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Console.log("==================> 自定义 ACCESS_TOKEN 被调用");

                if (principal instanceof UsernamePasswordAuthenticationToken auth) {
                    UserDetails user = (UserDetails) auth.getPrincipal();
                    context.getClaims().claims(claims -> {
                        claims.put("name", user.getUsername());
                        claims.put("roles", user.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList());
                        // 添加更多字段
                    });
                }
            } else if (OidcParameterNames.ID_TOKEN.equals(tokenType)) {
                Console.log("==================> 自定义 ID_TOKEN 被调用");
                context.getClaims().claims(claims -> {
                    // 这里可以完全设置 /userinfo 下的所有 claim 信息
                    claims.put("asFlag", "spirit");
                    claims.put("asVersion", "1.4.3");
                });
            }
        };
    }

}
