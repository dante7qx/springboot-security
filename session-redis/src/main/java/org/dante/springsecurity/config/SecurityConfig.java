package org.dante.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Spring Security5 必须要指定一个 PasswordEncoder
 * 
 * @author dante
 *
 */
@Configuration
public class SecurityConfig  {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withUsername("dante")
				.password("{bcrypt}$2a$10$s0Ta/mltqMGKzSNnpPGBqOyGtNtz4khC/N4r4NBtGwoF7i5xxSOTu")
				.roles("USER")
				.build();

		return new InMemoryUserDetailsManager(user);
	}

}
