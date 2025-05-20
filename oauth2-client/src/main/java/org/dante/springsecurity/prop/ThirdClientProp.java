package org.dante.springsecurity.prop;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "oauth2.third")
public class ThirdClientProp {

    private Client github;

    private Client gitee;

    private Client google;

    @Data
    public static class Client {
        private String clientId;
        private String clientSecret;
    }
}


