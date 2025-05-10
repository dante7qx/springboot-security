package org.dante.springsecurity.config;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.lang.Console;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.dao.Oauth2ClientKeypairDAO;
import org.dante.springsecurity.entity.Oauth2ClientKeypair;
import org.dante.springsecurity.security.KeyGeneratorUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 授权服务器配置
 *
 * @author dante
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    /**
     * 管理客户端Repo - 保存在内存中
     */
    /*
    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("spirit-client-id")
                .clientSecret(passwordEncoder.encode("spirit-client-secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // 客户端认证方式（推荐使用Basic Auth）
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)  // 密码模式
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)  // 授权码模式
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(30))
                        .reuseRefreshTokens(true)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .redirectUri("http://localhost:8001/login/oauth2/code/spirit-client-id")
                .scope("read")
                .scope("write")
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }
    */

    /**
     * 管理客户端Repo - 保存于数据库中
     *
     * Oauth2RegisteredClientService 已实现 RegisteredClientRepository 接口，无需重复定义 Bean。
     *
     * 待优化：缓存 JWK 响应
      */
    @Bean
    public JWKSource<SecurityContext> jwkSource(Oauth2ClientKeypairDAO keypairDAO) {
        return (jwkSelector, securityContext) -> {
            try {
                Console.log("==================> 从数据库加载所有有效的密钥对");
                List<Oauth2ClientKeypair> keypairs = keypairDAO.findValidKeys(Instant.now());
                List<JWK> jwks = CollUtil.newArrayList();
                if (CollUtil.isNotEmpty(keypairs)) {
                    jwks = keypairs.stream().map(k -> {
                        try {
                            RSAPublicKey publicKey = KeyGeneratorUtil.parsePublicKey(k.getPublicKeyPem());
                            RSAPrivateKey privateKey = KeyGeneratorUtil.parsePrivateKey(k.getPrivateKeyPem());
                            RSAKey jwk = new RSAKey.Builder(publicKey)
                                    .privateKey(privateKey)
                                    .keyID(k.getKeyId())
                                    .algorithm(JWSAlgorithm.RS256)
                                    .build();
                            Console.log("JWK 构建结果: {}", jwk.toJSONString());
                            return jwk;
                        } catch (Exception e) {
                            Console.log("密钥对解析失败: " + e.getMessage());
                            throw new IllegalStateException("Keypair 解析失败.", e);
                        }
                    }).collect(Collectors.toList());
                }
                return jwkSelector.select(new JWKSet(jwks));
            } catch (Exception e) {
                Console.log("发生异常: " + e.getMessage());
                throw new IllegalStateException("JWKSource 配置失败.", e);
            }
        };
    }

    /**
     * JWT 编码器
     * 将 JWT 的内容（Claims）和头部（Header）信息组合起来，并使用指定的加密算法进行签名，最终生成可用的 JWT 字符串
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        // 基于 Nimbus JOSE + JWT 库，自动从 JWKSource 选择合适的密钥进行签名
        NimbusJwtEncoder delegate = new NimbusJwtEncoder(jwkSource);
        return parameters -> {
            Console.log("==================> JwtEncoder.encode 被调用！");
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
    }

    /**
     * 统一异常响应
     * @return
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                // 添加自定义声明或处理逻辑
                Console.log("==================>{}", context.getJwsHeader().toString());
            }
        };
    }

    /**
     * 授权服务器Endpoint设置 (必配置项)
     *
     * 定义 OAuth 2.0 授权服务器的各种端点 URL 和服务器相关设置
     *
     * 配置项	                            默认值	                            说明
     * issuer	                            null	                        颁发者URI (RFC 8414)
     * authorizationEndpoint	            /oauth2/authorize	            授权
     * tokenEndpoint	                    /oauth2/token	                令牌
     * tokenIntrospectionEndpoint	        /oauth2/introspect	            令牌自省
     * tokenRevocationEndpoint	            /oauth2/revoke	                令牌撤销
     * jwkSetEndpoint	                    /oauth2/jwks	                JWK Set
     * oidcClientRegistrationEndpoint	    /connect/register	            OIDC客户端注册
     * oidcUserInfoEndpoint	                /userinfo	                    OIDC用户信息
     *
     * @return AuthorizationServerSettings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        AuthorizationServerSettings serverSettings = AuthorizationServerSettings.builder().build();
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8001")
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks.json")    // 同 clientSettings 下的 jwkSetUrl
                .build();
    }

}