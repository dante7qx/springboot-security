## Springboot + SpringSecurity

从 `Springboot 2.7` 升级到 `Springboot 3.4`，`Spring Security` 方面有一些重要的变化，特别是在配置方式和默认行为上。


### 1. 主要架构变化

- Spring Security 6 迁移到了 Jakarta EE 9+ 命名空间（jakarta.servlet 替代 javax.servlet）

- Spring Boot 3.x 需要 Java 17 或更高版本

### 2. antMatchers() 改为 requestMatchers()
```java
// 旧方式
http.authorizeRequests().antMatchers("/public/**").permitAll();

// 新方式
http.authorizeHttpRequests(auth -> auth.requestMatchers("/public/**").permitAll());
```

### 3. 密码编码

- NoOpPasswordEncoder 完全移除：不再支持明文密码存储

- 推荐使用 PasswordEncoder 的现代实现
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```
- 密码编码格式
```java
// {编码器ID}编码后的密码
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
{pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b
```

### 4. CSRF 保护
- 默认情况下 CSRF 保护对 /logout 禁用：需要显式配置
```java
// 忽略特定路径
http.csrf(csrf -> csrf.ignoringRequestMatchers("/custom-logout"));

// 禁用 csrf
http.csrf(AbstractHttpConfigurer::disable)

// 启用CSRF保护（默认已启用）
http.csrf(Customizer.withDefaults());
```
- 所有 POST 请求（包括登录）需要包含 CSRF token
    
    - Thymeleaf 自动处理
    - 纯HTML需要手动添加 
  
      `<input type="hidden" name="_csrf" th:value="${_csrf.token}"/>`

### 5. 不再自动生成默认登录页

- 需要显式配置
```java
http
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
```

- 自定义`login.html`