package org.dante.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    /**
     * 默认算法是 bcrypt
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/css/**", "/js/**").permitAll()     // 静态资源
                .requestMatchers("/api/public/**").permitAll()          // 公开端点
                .requestMatchers("/api/**").authenticated()             // 需要认证的端点
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")    // 指定登录页
                .defaultSuccessUrl("/")
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout=true")
                .permitAll()
            )
            .csrf(Customizer.withDefaults()); // 启用CSRF保护

        return http.build();
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
