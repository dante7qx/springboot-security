package org.dante.springsecurity.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.prop.AuthorizationProp;
import org.dante.springsecurity.security.KeyGeneratorUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.time.Duration;
import java.util.UUID;

/**
 * 授权服务器配置
 *
 * @author dante
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final AuthorizationProp authorizationProp;

    /**
     * 注册客户端 Repo
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(authorizationProp.getClientId())
                .clientSecret(passwordEncoder.encode(authorizationProp.getClientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Basic认证
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)        // 密码模式
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30)) // 设置令牌有效期
                        .reuseRefreshTokens(false) // 确保不重用 refresh_token（client_credentials 通常不需要）
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)    // 授权码模式
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(30))
                        .reuseRefreshTokens(true)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .redirectUri(authorizationProp.getRedirectUri())
                .scope("read")
                .scope("write")
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 配置 JWK 源
     *
     * JWK (JSON Web Key)：一种基于 JSON 的数据结构，表示加密密钥，包含密钥类型、算法、密钥ID等信息。
         {
             "kty": "RSA",
             "kid": "2023-01",
             "n": "modulus_value...",
             "e": "exponent_value..."
         }
     * 1. 提供动态获取 JWK 的机制
     * 2. 主要用于 JWT 签名验证时获取公钥
     * 3. 支持 OAuth 2.0/OIDC 提供商的密钥轮换
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = KeyGeneratorUtil.generateRsaKey(); // 生成 RSA 密钥
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
    }

    /**
     * JWT 编码器
     *
     * 将 JWT 的内容（Claims）和头部（Header）信息组合起来，并使用指定的加密算法进行签名，最终生成可用的 JWT 字符串
     *
     * @return
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        JWKSource<SecurityContext> jwkSource = jwkSource(); // 确保密钥正确加载
        return new NimbusJwtEncoder(jwkSource); // 基于 Nimbus JOSE + JWT 库，自动从 JWKSource 选择合适的密钥进行签名
    }

    /**
     * JWT 解码器
     *
     * 1. 授权服务器: 仅在授权服务器内部使用 JWT（如生成访问令牌）, 不需要 JWT 解码器
     * 2. 资源服务器: 需要验证 JWT 令牌（例如访问受保护 API），必须显式配置 JwtDecoder
     *
     * @param jwkSource
     * @return
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 负责生成各种 OAuth 2.0 令牌（如访问令牌(Access Token)、刷新令牌(Refresh Token)、授权码(Authorization Code)）

        1. 令牌生成中枢
            （1）统一生成 OAuth2 规范定义的所有令牌类型
            （2）包括访问令牌(Access Token)、刷新令牌(Refresh Token)、授权码(Authorization Code)
        2. 可扩展的生成策略
            （1）支持自定义令牌格式（JWT、不透明令牌等）
            （2）允许实现特定业务逻辑的令牌生成规则
        3. 与认证流程集成
            （1）被授权码模式、客户端凭证模式等所有授权流程使用
            （2）与令牌增强器(TokenEnhancer)协同工作

     * @param jwtEncoder
     * @return
     */
    @Bean
    public OAuth2TokenGenerator<?> jwtTokenGenerator(JwtEncoder jwtEncoder) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        // 生成器会按注册顺序执行, 第一个能处理当前令牌类型的生成器将被使用
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                accessTokenGenerator,
                refreshTokenGenerator
        );

//        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
//        return jwtGenerator;
    }

    /**
     * 授权服务器设置
     *
     * 定义 OAuth 2.0 授权服务器的各种端点 URL 和服务器相关设置
     *
     * 配置项	                            默认值	                            说明
     * issuer	                            null	                        颁发者URI (RFC 8414)
     * authorizationEndpoint	            /oauth2/authorize	            授权端点
     * tokenEndpoint	                    /oauth2/token	                令牌端点
     * tokenIntrospectionEndpoint	        /oauth2/introspect	            令牌自省端点
     * tokenRevocationEndpoint	            /oauth2/revoke	                令牌撤销端点
     * jwkSetEndpoint	                    /oauth2/jwks	                JWK Set端点
     * oidcClientRegistrationEndpoint	    /connect/register	            OIDC客户端注册端点
     * oidcUserInfoEndpoint	                /userinfo	                    OIDC用户信息端点
     *
     * @return AuthorizationServerSettings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        AuthorizationServerSettings serverSettings = AuthorizationServerSettings.builder().build();
        /*
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8001")
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .build();
        */
        return serverSettings;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> context.getClaims().claim("custom-claim", "custom-value");
    }

}

/*

  获取授权码：http://localhost:8001/oauth2/authorize?client_id=client-id&response_type=code&scope=read
  获取令牌：http://localhost:8001/oauth2/token

  测试：
    1. 先登录 http://localhost:8001/login
    2. 获取授权码： http://localhost:8001/oauth2/authorize?client_id=SpiritClientId&response_type=code&scope=read
        得到：http://localhost:8001/login/oauth2/code/SpiritClientId?code=LyP_ONR2U10R0u8olG-wqF-5aYbUAo8zC-bqiRdEQXF52C_CjnZ2AHqgMsolEvCAQ9NMBKn-68pZ3p2OZp3dBSmN94CFy7Ciz6ojHn6MaA2csxY96NqGHooE9VGplmac
    3. 获取Token（Basic Auth方式更安全）
		 curl -X POST "http://localhost:8001/oauth2/token" \
            -u "<你的client_id>:<你的client_secret>" \
		    -H "Content-Type: application/x-www-form-urlencoded" \
		 -d "grant_type=authorization_code&code=<你的授权码>&redirect_uri=http://localhost:8001/login/oauth2/code/<你的client_id>"

    curl -X POST "http://localhost:8001/oauth2/token" \
      -u "SpiritClientId:SpiritSecret" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=authorization_code&code=LyP_ONR2U10R0u8olG-wqF-5aYbUAo8zC-bqiRdEQXF52C_CjnZ2AHqgMsolEvCAQ9NMBKn-68pZ3p2OZp3dBSmN94CFy7Ciz6ojHn6MaA2csxY96NqGHooE9VGplmac&redirect_uri=http://localhost:8001/login/oauth2/code/SpiritClientId"


  密码模式：
     curl -X POST "http://localhost:8001/oauth2/token" \
         -u "<你的client_id>:<你的client_secret>" \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -d "grant_type=client_credentials&scope=read"

    curl -X POST "http://localhost:8001/oauth2/token" \
        -u "SpiritClientId:SpiritSecret" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&scope=read"
 */