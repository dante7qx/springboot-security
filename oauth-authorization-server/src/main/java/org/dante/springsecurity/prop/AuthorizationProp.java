package org.dante.springsecurity.prop;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "spirit")
public class AuthorizationProp {

    private String clientId;

    private String clientSecret;

    private String redirectUri;

    /** JWT签名密钥 */
    private String jwtKey;


}
