package org.dante.springsecurity.config;

import cn.hutool.core.lang.Console;
import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.service.OidcUserInfoService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.function.Function;

/**
 * 授权服务器配置
 *
 * @author dante
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final OidcUserInfoService userInfoService;

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
            .with(authorizationServerConfigurer, authorizationServer -> authorizationServer
                .oidc(oidc -> oidc
                    .userInfoEndpoint((userInfo) -> userInfo
                        .userInfoMapper(userInfoMapper())
                    )
                    // 自定义处理 oidcLogoutEndpoint （不推荐，应使用 Spring内部实现, 即注释掉下面这行 ）
//                    .logoutEndpoint(logout -> logout.logoutResponseHandler(new SpiritOidcLogoutHandler()))
//                    .Customizer.withDefaults()
            ))
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
        return AuthorizationServerSettings.builder()
                /*
                    公网地址（本地 OAuth2 Client 可用 localhost, 配置后，系统会自动暴露
                        /.well-known/openid-configuration
                        /.well-known/jwks.json （需自己实现）
                 */
                .issuer("http://localhost:8001")    // 其余都是默认配置，这个必须配置
//                .authorizationEndpoint("/oauth2/authorize")
//                .tokenEndpoint("/oauth2/token")
//                .jwkSetEndpoint("/oauth2/jwks")
                .oidcLogoutEndpoint("/connect/logout")  // 需要自定义 Endpoint 的处理逻辑
                .build();
    }

    /**
     * 自定义 userinfo 返回
     */
    private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper() {
        return (context) -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();

            Console.log("================> 自定义 userInfoMapper 被调用，当前用户 {}", principal.getName());
            return userInfoService.loadUser(principal);
        };
    }


}