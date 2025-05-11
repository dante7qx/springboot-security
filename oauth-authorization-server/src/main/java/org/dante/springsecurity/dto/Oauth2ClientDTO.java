package org.dante.springsecurity.dto;

import cn.hutool.core.util.IdUtil;
import lombok.Data;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;

@Data
public class Oauth2ClientDTO {

    private String clientId;

    private String clientSecret;

    private Instant issuedAt;

    private Instant expiresAt;

    private String grantType;   // 必须有授权方式

    private Oauth2ClientSettingsDTO clientSettings;

    /* 添加其他配置 AuthMethod、GrantType 等 */

    public RegisteredClient toRegisteredClient() {
        return RegisteredClient.withId(IdUtil.randomUUID())
                .clientId(this.clientId)
                .clientSecret(this.clientSecret)
                .clientIdIssuedAt(this.issuedAt)
                .clientSecretExpiresAt(this.expiresAt)
                .authorizationGrantType(new AuthorizationGrantType(this.grantType))
                .clientSettings(this.clientSettings.toClientSettings())
                .build();
    }
}
