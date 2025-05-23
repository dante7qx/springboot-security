package org.dante.springsecurity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * 创建一个支持 OAuth2 认证的 WebClient 实例
 */
@Configuration
public class WebClientConfig {

    @Value("${alipay.alipay-gateway}")
    private String alipayBaseUrl;

    @Bean
    @Primary
    public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

        return WebClient.builder()
                .apply(oauth2Client.oauth2Configuration())  // 应用OAuth2配置
                .build();
    }

    @Bean("alipayWebClient")
    public WebClient alipayWebClient() {
        return WebClient.builder()
                .baseUrl(alipayBaseUrl)
                .build();
    }
}

/*
    OAuth2AuthorizedClientManager  —  管理 OAuth2 客户端的授权流程（获取、刷新、保存访问令牌）
        1. 当需要访问令牌时，自动通过授权码流程、客户端凭证流程等获取令牌
        2. 在令牌过期时自动刷新
        3. 将授权后的客户端信息保存在 OAuth2AuthorizedClientRepository

    ServletOAuth2AuthorizedClientExchangeFilterFunction — 为 WebClient 添加 OAuth2 支持的处理过滤器
        1. 自动为出站请求添加 Authorization: Bearer <token> 头
        2. 根据请求的 registrationId 选择对应的客户端配置
        3. 处理令牌的自动刷新
*/