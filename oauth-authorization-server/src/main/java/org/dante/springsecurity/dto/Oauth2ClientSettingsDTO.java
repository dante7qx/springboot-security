package org.dante.springsecurity.dto;

import cn.hutool.core.util.StrUtil;
import lombok.Data;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.io.Serializable;

/**
 * 配置类 - 定义 OAuth2 客户端的行为
 *
 */
@Data
public class Oauth2ClientSettingsDTO implements Serializable {

    private String clientId;
    /** 是否需要用户授权 （true: 授权时会看到确认页面，必须手动同意权限）*/
    private Boolean requireProofKey = Boolean.FALSE;
    /** 是否启用 PKCE */
    private Boolean requireAuthorizationConsent = Boolean.FALSE;
    /** 客户端公钥存储地址 */
    private String jwkSetUri;
    /** JWT 认证算法 */
    private String tokenEndpointAuthSignAlg;

    public ClientSettings toClientSettings() {
        ClientSettings.Builder builder = ClientSettings.builder();
        builder.requireProofKey(this.requireProofKey).requireAuthorizationConsent(this.requireAuthorizationConsent);

        if(StrUtil.isNotEmpty(this.jwkSetUri)) {
            builder.jwkSetUrl(this.jwkSetUri);
        }
        if(StrUtil.isNotEmpty(this.tokenEndpointAuthSignAlg)) {
            builder.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.from(this.tokenEndpointAuthSignAlg));
        }
        return builder.build();
    }

    public static Oauth2ClientSettingsDTO from(Oauth2ClientDTO client, ClientSettings settings) {
        Oauth2ClientSettingsDTO entity = new Oauth2ClientSettingsDTO();
        entity.setClientId(client.getClientId());
        entity.setRequireProofKey(settings.isRequireProofKey());
        entity.setRequireAuthorizationConsent(settings.isRequireAuthorizationConsent());
        entity.setJwkSetUri(settings.getJwkSetUrl());
        JwsAlgorithm algo = settings.getTokenEndpointAuthenticationSigningAlgorithm();
        if (algo != null) {
            entity.setTokenEndpointAuthSignAlg(algo.getName());
        }
        return entity;
    }

}

/**
 PKCE 认证流程

 PKCE 在 OAuth 2.0 授权码模式 的基础上，增加了 code_verifier 和 code_challenge：

 1. 客户端生成 code_verifier（一个随机字符串）
 2. 客户端计算 code_challenge（code_verifier 的哈希值）
 3. 客户端在授权请求中发送 code_challenge
 4. 授权服务器返回授权码
 5. 客户端用 code_verifier 交换访问令牌
 6. 授权服务器验证 code_verifier 是否匹配 code_challenge

 如果 code_verifier 不匹配，授权服务器会拒绝令牌请求。

 示例:
 // 授权请求
 GET /authorize?response_type=code
 &client_id=my-client
 &code_challenge=hash(abc123)
 &code_challenge_method=S256

 // 令牌请求
 POST /token
 grant_type=authorization_code
 &code=xyz789
 &code_verifier=abc123

 */