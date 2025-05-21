package org.dante.springsecurity.service;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.StrUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.dao.*;
import org.dante.springsecurity.entity.*;
import org.dante.springsecurity.prop.AuthorizationProp;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * 自定义 RegisteredClientRepository
 *   1. 存储 OAuth2 客户端信息（如 client_id、client_secret）
 *   2. 检索已注册的客户端（用于身份验证）
 */
@Repository
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class Oauth2RegisteredClientService implements RegisteredClientRepository {

    private final Oauth2ClientDAO clientDAO;
    private final Oauth2ClientAuthMethodDAO authMethodDAO;
    private final Oauth2ClientGrantTypeDAO grantTypeDAO;
    private final Oauth2ClientRedirectUriDAO redirectUriDAO;
    private final Oauth2ClientScopeDAO scopeDAO;
    private final Oauth2ClientPostLogoutRedirectUriDAO logoutRedirectUriDAO;
    private final Oauth2ClientTokenSettingsDAO tokenSettingsDAO;
    private final Oauth2ClientSettingDAO settingDAO;
    private final Oauth2ClientKeypairService keypairService;
    private final PasswordEncoder passwordEncoder;
    private final AuthorizationServerSettings serverSettings;
    private final AuthorizationProp authProp;

    /**
     * 将 RegisteredClient 存入 DB
     */
    @Override
    @Transactional
    public void save(RegisteredClient client) {
        clientDAO.findById(client.getId())
                .ifPresentOrElse(
                        existing -> updateExisting(existing, client),
                        () -> createNew(client)
                );
    }

    private void createNew(RegisteredClient client) {
        Oauth2Client entity = toNewEntity(client);
        buildAssociationEntity(entity, client);
        clientDAO.save(entity);
    }

    private void updateExisting(Oauth2Client entity, RegisteredClient client) {
        // 只更新允许修改的字段
        if(StrUtil.isNotEmpty(client.getClientSecret())) {
            entity.setClientSecret(passwordEncoder.encode(client.getClientSecret()));
        }
        entity.setExpiresAt(client.getClientSecretExpiresAt());
        buildAssociationEntity(entity, client);
        clientDAO.save(entity);
    }

    private Oauth2Client toNewEntity(RegisteredClient client) {
        Oauth2Client entity = new Oauth2Client(client.getId());
        entity.setClientId(client.getClientId());
        if(StrUtil.isNotEmpty(client.getClientSecret())) {
            entity.setClientSecret(passwordEncoder.encode(client.getClientSecret()));
        }
        entity.setIssuedAt(client.getClientIdIssuedAt());
        entity.setExpiresAt(client.getClientSecretExpiresAt());
        entity.setExpiresAt(client.getClientSecretExpiresAt());

        return entity;
    }

    /**
     * 构建关联实体集合
     */
    private void buildAssociationEntity(Oauth2Client entity, RegisteredClient client) {
        // 认证方式
        authMethodDAO.deleteByClientId(entity.getId());
        entity.getAuthMethods().clear();
        client.getClientAuthenticationMethods().forEach(method ->
            entity.getAuthMethods().add(Oauth2ClientAuthMethod.from(entity, method))
        );

        // 授权类型
        grantTypeDAO.deleteByClientId(entity.getId());
        entity.getGrantTypes().clear();
        client.getAuthorizationGrantTypes().forEach(grantType ->
            entity.getGrantTypes().add(Oauth2ClientGrantType.from(entity, grantType))
        );

        // 回调Uri
        redirectUriDAO.deleteByClientId(entity.getId());
        entity.getRedirectUris().clear();
        client.getRedirectUris().forEach(redirectUri ->
            entity.getRedirectUris().add(Oauth2ClientRedirectUri.from(entity, redirectUri))
        );

        // 权限范围
        scopeDAO.deleteByClientId(entity.getId());
        entity.getScopes().clear();
        client.getScopes().forEach(scope ->
            entity.getScopes().add(Oauth2ClientScope.from(entity, scope))
        );

        // oidc logout 回调 Uri
        logoutRedirectUriDAO.deleteByClientId(entity.getId());
        entity.getLogoutRedirectUris().clear();
        client.getPostLogoutRedirectUris().forEach(redirectUri ->
            entity.getLogoutRedirectUris().add(Oauth2ClientPostLogoutRedirectUri.from(entity, redirectUri))
        );

        // Token 设置
        tokenSettingsDAO.deleteByClientId(entity.getId());
        entity.setTokenSettings(Oauth2ClientTokenSettings.from(entity, client.getTokenSettings()));

        // 配置客户端的行为
        settingDAO.deleteByClientId(entity.getId());
        entity.setClientSettings(Oauth2ClientSettings.from(entity, client.getClientSettings()));

    }

    /**
     * 根据 id 查询客户端信息
     */
    @Override
    public RegisteredClient findById(String id) {
        return clientDAO.findById(id)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    /**
     * 根据 clientId 查询客户端信息（OAuth2 认证时使用）
     */
    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientDAO.findByClientId(clientId)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient toRegisteredClient(Oauth2Client entity) {
        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret())
                .clientIdIssuedAt(entity.getIssuedAt());

        // 添加关联属性
        entity.getAuthMethods().forEach(method -> builder.clientAuthenticationMethod(method.toMethod()));
        entity.getGrantTypes().forEach(grantType -> builder.authorizationGrantType(grantType.toGrantType()));
        entity.getRedirectUris().forEach(uri -> builder.redirectUri(uri.getRedirectUri()));
        entity.getScopes().forEach(scope -> builder.scope(scope.getScope()));
        entity.getLogoutRedirectUris().forEach(uri -> builder.postLogoutRedirectUri(uri.getLogoutRedirectUri()));
        builder.tokenSettings(entity.getTokenSettings().toTokenSettings());
        builder.clientSettings(entity.getClientSettings().toClientSettings());
        return builder.build();
    }

    /**
     * 模拟Client数据，正式环境需要管理后台
     */
    @PostConstruct
    @Transactional
    public void initClient() {
        String clientId1 = "secret-basic-client", clientSecret1 = "secret-basic-secret";
        if (clientDAO.findByClientId(clientId1).isEmpty()) {
            this.save(secretBasicClient(clientId1, clientSecret1)); // client_secret 作为密钥，不需要密钥对
        }
        String clientId2 = "private-key-client";
        if (clientDAO.findByClientId(clientId2).isEmpty()) {
            this.save(privateKeyClient(clientId2));
            keypairService.generateKeypair(clientId2);  // 生成密钥对（耗时操作）
        }
    }

    /**
     * 构造Basic Auth认证的Client
     */
    private RegisteredClient secretBasicClient(String clientId, String clientSecret) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientIdIssuedAt(Instant.now())
                .clientSecretExpiresAt(DateUtil.endOfMonth(DateUtil.date()).toInstant())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // 客户端认证方式（推荐使用Basic Auth）
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);  // 授权码模式
                })
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(3))
                        .reuseRefreshTokens(true)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)     // OAuth2TokenFormat.REFERENCE、SELF_CONTAINED
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)                      // 用户授权确认
                        // BackChannel Logout 当前版本不可用
                        .setting("backchannel_logout_uri", authProp.getClientBaseUrl() + "/backchannel-logout")
                        .setting("backchannel_logout_session_required", true)
                        .build())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(authProp.getClientBaseUrl() + "/login/oauth2/code/" + clientId)
                .postLogoutRedirectUri(authProp.getClientBaseUrl() + "/logout-success")
                .scopes(scopes -> {
                    scopes.add(OidcScopes.OPENID);   // 核心 scope, 表明这是一个 OIDC 请求
                    scopes.add(OidcScopes.PROFILE);
                    scopes.add(OidcScopes.EMAIL);
                    scopes.add("api.book.read");
                    scopes.add("api.book.write");
                })
                .build();
    }


    /**
     * 构造私钥认证的Client（服务器间通信）
     * CLIENT_CREDENTIALS 模式下，无须 redirectUri
     * PRIVATE_KEY_JWT 认证方式，必须显式声明签名算法
     */
    private RegisteredClient privateKeyClient(String clientId) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientIdIssuedAt(Instant.now())
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)     // JWT 认证方式
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);  // 密码模式（服务器间通信（无用户交互））
                })
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(3))
                        .reuseRefreshTokens(true)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)                     // 服务器之间通信，不需要用户授权
                        .jwkSetUrl(serverSettings.getIssuer() + serverSettings.getJwkSetEndpoint())
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)  // 必须显式声明签名算法
                        .build())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .scope(OidcScopes.OPENID)
                .scope("api.book.read")
                .scope("api.book.write")
                .build();
    }

}
