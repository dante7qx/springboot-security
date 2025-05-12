package org.dante.springsecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserController {
	
	@GetMapping("/users/extra")
	public Map<String, Object> getExtraInfo(Authentication auth) {
        return Map.of();
    }

}
