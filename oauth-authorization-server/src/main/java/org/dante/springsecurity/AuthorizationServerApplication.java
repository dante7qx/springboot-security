package org.dante.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Security OAuth2 认证服务器
 * 
 * @author dante
 *
 */
@SpringBootApplication
public class AuthorizationServerApplication {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(AuthorizationServerApplication.class, args);
	}

	
}
