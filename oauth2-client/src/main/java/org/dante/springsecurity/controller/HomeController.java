package org.dante.springsecurity.controller;

import cn.hutool.core.lang.Console;
import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.prop.SpiritClientProp;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final WebClient webClient;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final SpiritClientProp spiritClientProp;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/home")
    public String home(@AuthenticationPrincipal OAuth2User principal, Model model) {
        Console.log("================================================> 授权登录成功！");
        model.addAttribute("userName", principal.getAttribute("name"));
        model.addAttribute("userAttributes", principal.getAttributes());
        return "home";
    }

    @GetMapping("/resource")
    public String getResource(@RegisteredOAuth2AuthorizedClient("secret-basic-client") OAuth2AuthorizedClient authorizedClient, Model model) {
        // 使用访问令牌调用资源服务器
        String resourceResponse = webClient
                .get()
                .uri(spiritClientProp.getResourceServerUrl()+ "/api/book/200") // 资源服务器的API地址
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        model.addAttribute("resourceResponse", resourceResponse);
        return "resource";
    }
}
