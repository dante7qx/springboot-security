package org.dante.springsecurity.entity;

import cn.hutool.core.util.StrUtil;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Duration;
import java.util.UUID;

/**
 * 配置类 - 定义 OAuth2 令牌的相关设置
 *  1. Access Token 的格式（JWT 或 Opaque）
 *  2. 设置令牌的有效期
 *  3. 定义 ID Token 的签名算法
 *  4. 是否允许重复使用 refresh_token
 *
 */
@Entity
@Table(name = "oauth2_client_token_settings")
@Data
@ToString(exclude = "client")
@EqualsAndHashCode(exclude = "client")
public class Oauth2ClientTokenSettings implements Serializable {

    @Id
    private String id;
    @OneToOne
    @JoinColumn(name = "client_id")
    private Oauth2Client client;
    /** 单位：秒。访问令牌有效期, 默认 5 分钟 */
    private Long accessTokenTimeToLive;
    /** 单位：秒。刷新令牌有效期, 默认 30 天 */
    private Long refreshTokenTimeToLive;
    /** 是否允许重复使用 refresh_token */
    private Boolean reuseRefreshToken = Boolean.TRUE;
    /** 令牌格式（JWT 或 Opaque("reference")）, 默认 JWT ("self-contained") */
    private String accessTokenFormat;
    /** ID Token 签名算法，默认 RS256 */
    private String idTokenSignatureAlgorithm;

    public Oauth2ClientTokenSettings() {
        this.id = UUID.randomUUID().toString();
    }

    public TokenSettings toTokenSettings() {
        TokenSettings.Builder builder = TokenSettings.builder();
        if(this.accessTokenTimeToLive > 0) {
            builder.accessTokenTimeToLive(Duration.ofSeconds(this.accessTokenTimeToLive));
        }
        if(this.refreshTokenTimeToLive > 0) {
            builder.refreshTokenTimeToLive(Duration.ofSeconds(this.refreshTokenTimeToLive));
        }
        builder.reuseRefreshTokens(this.reuseRefreshToken);
        if(StrUtil.isNotEmpty(this.accessTokenFormat)) {
            builder.accessTokenFormat(new OAuth2TokenFormat(this.accessTokenFormat));
        }
        if(StrUtil.isNotEmpty(this.idTokenSignatureAlgorithm)) {
            builder.idTokenSignatureAlgorithm(SignatureAlgorithm.from(this.idTokenSignatureAlgorithm));
        }
        return builder.build();
    }

    public static Oauth2ClientTokenSettings from(Oauth2Client client, TokenSettings settings) {
        Oauth2ClientTokenSettings entity = new Oauth2ClientTokenSettings();
        entity.setClient(client);
        entity.setAccessTokenTimeToLive(settings.getAccessTokenTimeToLive().toSeconds());
        entity.setRefreshTokenTimeToLive(settings.getRefreshTokenTimeToLive().toSeconds());
        entity.setReuseRefreshToken(settings.isReuseRefreshTokens());
        entity.setAccessTokenFormat(settings.getAccessTokenFormat().getValue());
        SignatureAlgorithm algo = settings.getIdTokenSignatureAlgorithm();
        if (algo != null) {
            entity.setIdTokenSignatureAlgorithm(algo.getName());
        }
        return entity;
    }
}

/**
JWT vs Opaque Token
    Spring Authorization Server 支持两种令牌格式：
     1. JWT（Self-contained） → 令牌包含所有信息，资源服务器可以直接解析
     2. Opaque Token（Reference） → 令牌是一个随机字符串，资源服务器需要向授权服务器验证
 */
