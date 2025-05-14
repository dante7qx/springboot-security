package org.dante.springsecurity.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    /**
     * Spring Security 会自动将用户信息注入 Principal
     */
    @GetMapping("/user")
    public String userInfo(@AuthenticationPrincipal OAuth2User principal) {
        return "Hello, " + principal.getAttribute("name") + "!";
    }

    @GetMapping("/info")
    public String info() {
        return "Welcome to the Home Page!";
    }

}
