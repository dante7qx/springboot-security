package org.dante.springsecurity.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class UserController {

	@RequestMapping("/user/me")
    public Principal user(Principal principal) {
        log.info("认证主体：{}", principal);
        return principal;
    }
	
}
