## OAuth2 资源服务器

资源服务器（Resource Server）是指能够提供受保护资源，并且可以接受和处理带有访问令牌（Access Token）的请求的服务器。
简单来说，一旦资源所有者授权了第三方客户端应用访问其资源，客户端就可以通过携带有效的访问令牌来向资源服务器发起请求，以访问这些受保护的资源。

- **验证访问令牌**：

  资源服务器需要有能力验证客户端提供的访问令牌的有效性。这通常涉及到检查令牌签名、过期时间、颁发者信息等。

- **权限控制**：

  基于访问令牌中包含的范围（scopes）或者其它声明信息，资源服务器决定是否允许请求访问特定的资源。

- **与授权服务器协作**：

  虽然资源服务器负责保护资源并验证访问令牌，但它通常依赖于授权服务器（Authorization Server）来生成这些令牌。某些情况下，资源服务器可能会直接集成授权服务器的功能，但在更常见的情况下，这两者是分离的。


**整体思路**

1. 创建新的`Spring Boot`应用作为资源服务器
2. 配置`OAuth2`资源服务器安全设置
3. 配置`JWT`令牌验证
4. 实现资源接口
5. 配置权限控制
6. 自定义错误处理

**主要依赖**
```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
```

**yml配置**
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:  # 使用您的授权服务器的JWK Set URI
          issuer-uri: http://localhost:8001
          jwk-set-uri: http://localhost:8001/oauth2/jwks
```

**安全配置**
```java
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
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 1. 资源服务器自己的用户、权限
     * 2. 客户端的 scope 通过授权服务器的后台进行配置
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // 查询权限
        UserDetails userRead = User.withUsername("dante")
                .password("{bcrypt}$2a$10$s0Ta/mltqMGKzSNnpPGBqOyGtNtz4khC/N4r4NBtGwoF7i5xxSOTu")
                .authorities("api.book.read")
                .build();

        // 编辑权限
        UserDetails userWrite = User.withUsername("snake")
                .password("{bcrypt}$2a$10$s0Ta/mltqMGKzSNnpPGBqOyGtNtz4khC/N4r4NBtGwoF7i5xxSOTu")
                .authorities("api.book.write")
                .build();

        // 管理员权限
        UserDetails admin = User.withUsername("admin")
                .password("{bcrypt}$2a$10$s0Ta/mltqMGKzSNnpPGBqOyGtNtz4khC/N4r4NBtGwoF7i5xxSOTu")
                .authorities("api.book.read", "api.book.write")
                .build();

        return new InMemoryUserDetailsManager(userRead, userWrite, admin);
    }

}
```

**推荐设计**

1. 资源服务器不维护用户，统一用户中心
2. 授权服务器上管理`资源服务器`注册，`资源服务器的 scope`，以及与`客户端`的`scope`映射关系