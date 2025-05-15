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
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
     * 授权服务器的安全控制（高优先级）
     * 授权码模式下: 资源所有者需要通过身份验证。因此，除了默认的 OAuth2 安全配置外，还必须配置用户身份验证机制, 即: AuthenticationManager
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        // 获取所有OAuth2授权服务器端点的匹配器
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http
            .securityMatcher(endpointsMatcher)
            .with(authorizationServerConfigurer, asConfig -> {})
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
            .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher)); // 对所有授权服务器端点禁用 CSRF
        return http.build();
    }

    /*
     * 管理客户端Repo - 保存于数据库中
     * Oauth2RegisteredClientService 已实现 RegisteredClientRepository 接口，无需重复定义 Bean。
     */

    /**
     * 授权服务器Endpoint设置 (必配置项)
     * <p>
     * 定义 OAuth 2.0 授权服务器的各种端点 URL 和服务器相关设置
     * <p>
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
                .jwkSetEndpoint("/oauth2/jwks")    // 同 clientSettings 下的 jwkSetUrl
                .build();
    }

}