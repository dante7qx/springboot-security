package org.dante.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Spring Security5 必须要指定一个 PasswordEncoder
 *
 * @author dante
 */
@Configuration
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
    // 2.5 配置
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
            .withUser("dante")
            .password("$2a$10$G4Io4382I2d9yXqn0mFf.uU8ObvYw4L9X/JLgsUTu/sG3/gGfQG/u")
            .roles("USER");
    }
     */

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("dante")
                .password("$2a$10$G4Io4382I2d9yXqn0mFf.uU8ObvYw4L9X/JLgsUTu/sG3/gGfQG/u")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }


}
