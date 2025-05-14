package org.dante.springsecurity.controller.api.pubilc;

import org.dante.springsecurity.controller.api.BaseApiController;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/public")
public class PublicApiController extends BaseApiController {
	
	@GetMapping
	public String getInfo() {
        return "我是一台基于 Spring Security OAuth2 Resource Server  的资源服务器";
    }

    @GetMapping("/{wish}")
    public String greeting(@PathVariable("wish") String wish) {
        return "欢迎，祝您 " + wish;
    }

}