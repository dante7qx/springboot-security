package org.dante.springsecurity.prop;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "spirit")
public class SpiritClientProp {

    /** 授权服务器地址 */
    private String authServerUrl;

    /** 资源服务器地址 */
    private String resourceServerUrl;
}





