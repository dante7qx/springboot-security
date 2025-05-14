package org.dante.springsecurity.prop;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "spirit")
public class AuthorizationProp {
    /** 客户端地址 */
    private String clientBaseUrl;
}
