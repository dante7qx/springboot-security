package org.dante.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Security OAuth2 
 * 参考：https://blog.csdn.net/qq_31635851/article/details/120706389
 * 
 * @author dante
 *
 */
@SpringBootApplication
public class AuthorizationCodeClientApplication {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(AuthorizationCodeClientApplication.class, args);
	}

	
}
