package org.dante.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final SpiritOAuth2UserService oAuth2UserService;
    private final SpiritOidcUserService oidcUserService;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/", "/login", "/error", "/logout", "/logout-success").permitAll()
                .requestMatchers("/css/**", "/js/**", "/img/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/")                                            // 自定义登录页
                .defaultSuccessUrl("/home", true)
                .failureUrl("/?error=true")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(oAuth2UserService)
                    .oidcUserService(oidcUserService)
                )
            )
            .logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler())
                // 客户端 local 注销
//                .logoutSuccessUrl("/")
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID")
            );

        return http.build();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRepo, OAuth2AuthorizedClientRepository authorizedClientRepo) {
        OAuth2AuthorizedClientProvider clientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .clientCredentials()
                        .build();
        DefaultOAuth2AuthorizedClientManager clientManager = new DefaultOAuth2AuthorizedClientManager(clientRepo, authorizedClientRepo);
        clientManager.setAuthorizedClientProvider(clientProvider);
        return clientManager;
    }

    /**
     * 单点登出 SLO
     * 设置一个 Location, 在用户（End-User）的客户端在身份提供方（授权服务器、身份认证服务器）完成注销操作后，将被重定向到这个位置
     * 在OAuth 2.0/OpenID Connect的注销流程中，这个参数通常叫post_logout_redirect_uri
     */
    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        /*
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/logout-success");
        return oidcLogoutSuccessHandler;
        */

        OidcClientInitiatedLogoutSuccessHandler oidcHandler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        oidcHandler.setPostLogoutRedirectUri("{baseUrl}/logout-success");

        return (request, response, authentication) -> {
            if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
                String registrationId = oauth2Token.getAuthorizedClientRegistrationId();

                // 不支持 OIDC, 进行本地注销操作
                if ("github".equals(registrationId) || "gitee".equals(registrationId)) {
                    // GitHub 不支持 OIDC logout，仅清理 session
                    request.logout();
                    response.sendRedirect("/client"); // 或跳转到登录页
                    return;
                }

                // OIDC 处理（本地 AS）
                oidcHandler.onLogoutSuccess(request, response, authentication);
            } else {
                // 非 OAuth2 登录，默认登出处理
                response.sendRedirect("/");
            }
        };


    }

}
