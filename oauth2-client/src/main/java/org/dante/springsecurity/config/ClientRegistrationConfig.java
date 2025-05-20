package org.dante.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.prop.SpiritClientProp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

@Configuration
@RequiredArgsConstructor
public class ClientRegistrationConfig {

    private final SpiritClientProp clientProp;

    /**
     * 懒加载 OIDC discovery
     * 通过 JavaConfig 方式注册 ClientRegistrationRepository，推迟 issuer-uri 的解析，直到真正发起登录请求再触发
     * 目的，若 AS 未启动，Client 也能正常启动
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
                this.spiritClientRegistration(),
                this.githubClientRegistration(),
                this.giteeClientRegistration(),
                this.googleClientRegistration()
        );
    }

    private ClientRegistration spiritClientRegistration() {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(clientProp.getClientId())
                .clientId(clientProp.getClientId())
                .clientSecret(clientProp.getClientSecret())
                .clientName(clientProp.getClientName())
                .authorizationGrantType(new AuthorizationGrantType(clientProp.getAuthorizationGrantType()))
                .redirectUri(clientProp.getRedirectUri())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(clientProp.getClientAuthenticationMethod()))
                .scope(clientProp.getScope());
        if (clientProp.getEnableIssuer()) {
            builder.issuerUri(clientProp.getAuthServerUrl());
        } else {
            builder.authorizationUri(clientProp.getAuthServerUrl() + "/oauth2/authorize")
                    .tokenUri(clientProp.getAuthServerUrl() + "/oauth2/token")
                    .jwkSetUri(clientProp.getAuthServerUrl() + "/oauth2/jwks");
        }
        return builder.build();
    }

    private ClientRegistration githubClientRegistration() {
        return ClientRegistration.withRegistrationId("github")
                .clientName("Github 登录")
                .clientId("2a072c55d48f194676f7")
                .clientSecret("c816673448d997ca8adda06418c689ac8fe513cb")
                .scope("public_repo", "read:user", "user:email")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://6ca39297.r21.cpolar.top/client/login/oauth2/code/{registrationId}")
                .authorizationUri("https://github.com/login/oauth/authorize")
                .tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri("https://api.github.com/user")
                .userNameAttributeName("login")
                .build();
    }

    private ClientRegistration giteeClientRegistration() {
        return ClientRegistration.withRegistrationId("gitee")
                .clientName("Gitee 登录")
                .clientId("168ef86abab1300b44b36b9858484c89980a8919434c1958f5c60a860867cf81")
                .clientSecret("b0b21c4ff73c5db0b483d60779e03127b54cd93661e3e78e3f4e1479b74374ee")
                .scope("user_info", "projects")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://6ca39297.r21.cpolar.top/client/login/oauth2/code/{registrationId}")
                .authorizationUri("https://gitee.com/oauth/authorize")
                .tokenUri("https://gitee.com/oauth/token")
                .userInfoUri("https://gitee.com/api/v5/user")
                .userNameAttributeName("login")
                .build();
    }

    private ClientRegistration googleClientRegistration() {
        return ClientRegistration.withRegistrationId("google")
                .clientName("Google 登录")
                .clientId("563132197681-1torjlvhl24tu66oqtf40qp115kvp9ct.apps.googleusercontent.com")
                .clientSecret("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")
                .scope("openid", "profile", "email")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://6ca39297.r21.cpolar.top/client/login/oauth2/code/{registrationId}")
                .issuerUri("https://accounts.google.com")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .tokenUri("https://oauth2.googleapis.com/token")
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .build();
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }
}
/*
## yaml 配置

  secret-basic-client:           # 自定义客户端名称（可随意命名）, 自动注入为一个 ClientRegistration Bean
    client-id: secret-basic-client
    client-secret: secret-basic-secret
    client-name: "Spirit 客户端"
    authorization-grant-type: authorization_code # authorization_code, client_credentials, password, urn:ietf:params:oauth:grant-type:jwt-bearer
    scope: openid,email,api.book.read,api.book.write
    client-authentication-method: client_secret_basic # client_secret_basic, client_secret_post, private_key_jwt, client_secret_jwt and none
    redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"      # 通常是 {baseUrl}/login/oauth2/code/{registrationId}
    provider: spirit-provider     # 关联的授权服务器配置
  provider:                                                           # 对于内置支持的 provider（如 GitHub、Google），不需要 provider 节点。对 Gitee、微信等则需提供 provider 信息
    spirit-provider:
      issuer-uri: ${spirit.auth-server-url}
#     authorization-uri: ${spirit.auth-server-url}/oauth2/authorize
#     token-uri: ${spirit.auth-server-url}/oauth2/token/
#     jwk-set-uri: ${spirit.auth-server-url}/oauth2/jwks
#     user-info-uri: ${spirit.auth-server-url}/userinfo
 */