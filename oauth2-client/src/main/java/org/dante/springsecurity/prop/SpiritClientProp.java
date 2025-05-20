package org.dante.springsecurity.prop;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "spirit")
public class SpiritClientProp {

    private String clientId;

    private String clientSecret;

    private String clientName;

    private String authorizationGrantType;

    private String[] scope;

    private String clientAuthenticationMethod;

    private String redirectUri;

    /** 启用 OIDC Discovery (启动阶段 拉取远程的 /.well-known/openid-configuration) */
    private Boolean enableIssuer = Boolean.TRUE;

    /** 授权服务器地址 */
    private String authServerUrl;

    /** 资源服务器地址 */
    private String resourceServerUrl;

}





