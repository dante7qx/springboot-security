package org.dante.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 第一个 Spring Security 应用
 * 
 * @author dante
 *
 */
@SpringBootApplication
public class SessionRedisApplication {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(SessionRedisApplication.class, args);
	}


}
