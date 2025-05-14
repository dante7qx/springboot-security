package org.dante.springsecurity.config;

import org.dante.springsecurity.security.SpiritAccessDeniedHandler;
import org.dante.springsecurity.security.SpiritAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 配置安全规则, 开启方法验证
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> authorize
                .antMatchers("/api/public/**").permitAll()   // 公开端点
                .antMatchers("/api/**").authenticated()  // 需要认证的端点
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())) // 自定义权限映射
            )
            .exceptionHandling(exceptions -> exceptions
                    .authenticationEntryPoint(new SpiritAuthenticationEntryPoint())
                    .accessDeniedHandler(new SpiritAccessDeniedHandler())
            );;
        return http.build();
    }

    /**
     * 自定义JWT转换器，将JWT中的claims转换为Spring Security的权限
     * 使用了JWT，并正确配置了资源服务器，Spring Security 会自动将认证后的用户信息注入为 OAuth2AuthenticatedPrincipal 或者 Jwt (默认注入的是 Jwt)
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("scope");
        authoritiesConverter.setAuthorityPrefix(""); // 移除默认的"SCOPE_"前缀

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 1. 资源服务器自己的用户、权限
     * 2. 客户端的 scope 通过授权服务器的后台进行配置
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // 查询权限
        UserDetails userRead = User.withUsername("dante")
                .password("$2a$10$G4Io4382I2d9yXqn0mFf.uU8ObvYw4L9X/JLgsUTu/sG3/gGfQG/u")
                .authorities("api.book.read")
                .build();

        // 编辑权限
        UserDetails userWrite = User.withUsername("snake")
                .password("$2a$10$G4Io4382I2d9yXqn0mFf.uU8ObvYw4L9X/JLgsUTu/sG3/gGfQG/u")
                .authorities("api.book.write")
                .build();

        // 管理员权限
        UserDetails admin = User.withUsername("admin")
                .password("$2a$10$G4Io4382I2d9yXqn0mFf.uU8ObvYw4L9X/JLgsUTu/sG3/gGfQG/u")
                .authorities("api.book.read", "api.book.write")
                .build();

        return new InMemoryUserDetailsManager(userRead, userWrite, admin);
    }

}
