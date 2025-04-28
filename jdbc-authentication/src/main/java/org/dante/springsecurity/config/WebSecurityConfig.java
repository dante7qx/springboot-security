package org.dante.springsecurity.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Spring Security5 必须要指定一个 PasswordEncoder
 * 
 * @author dante
 *
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final DataSource dataSource;

	public WebSecurityConfig(DataSource dataSource) {
		this.dataSource = dataSource;
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Autowired
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
		.jdbcAuthentication()
		.dataSource(dataSource)
		.withDefaultSchema()
		.withUser(User.withUsername("dante").password("$2a$10$G4Io4382I2d9yXqn0mFf.uU8ObvYw4L9X/JLgsUTu/sG3/gGfQG/u").roles("USER"))
		;
	}
	
}
