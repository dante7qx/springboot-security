## Springboot + SpringSecurity

从 `Springboot 2.5` 升级到 `Springboot 2.7`，`Spring Security` 方面有一些重要的变化，特别是在配置方式和默认行为上。


### 1. WebSecurityConfigurerAdapter 被弃用

在 `Spring Boot 2.7`（对应 `Spring Security 5.7`）中，`WebSecurityConfigurerAdapter`被正式弃用，推荐使用`SecurityFilterChain`进行配置：

- 2.5 版本

继承`WebSecurityConfigurerAdapter`并重写`configure(HttpSecurity http)`方法
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/public").permitAll()
            .anyRequest().authenticated();
    }
}
```

- 2.7 版本

直接声明配置类，再配置一个生成`SecurityFilterChainBean`的方法，把原来的`HttpSecurity`配置移动到该方法中即可
```java
// 不需要 @EnableWebSecurity，因为 @Configuration + @Bean 已经足够
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/public").permitAll()
            .anyRequest().authenticated());
        return http.build();
    }
}
```

### 2. `PasswordEncoder`默认实现变化

- 2.5 版本

默认使用 NoOpPasswordEncoder（不推荐）

- 2.7 版本

推荐使用 BCryptPasswordEncoder，并且 NoOpPasswordEncoder 需要手动配置
    
### 3. `AuthenticationManager`配置方式变化

在 Spring Boot 2.7 之后，AuthenticationManager 不能直接通过 WebSecurityConfigurerAdapter 获取，而是需要手动定义

```java
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
}
```

### 3. DSL 语法

`Spring Boot 2.7` 采用更简洁的 `DSL` 语法，减少了冗余代码。

### 4. 默认开启 CSRF 保护

在`·Spring Boot 2.7` 中，如果你引入了 Spring Security，它默认开启 CSRF 防护。

(1) POST、PUT、DELETE、PATCH 等 非 GET/HEAD/OPTIONS/TRACE 请求 都需要带上有效的 CSRF token。

(2) 如果前端请求中没有携带正确的 CSRF token，Spring Security 会返回 403 Forbidden。

- 关闭 CSRF
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf().disable() // 关闭CSRF保护
        .authorizeRequests()
            .anyRequest().authenticated()
        .and()
        .formLogin(); // 开启表单登录
    return http.build();
}
```

- 正确使用 CSRF Token（前后端交互）

1. 如果是表单提交（<form>），`Spring Security` 会自动在表单中插入隐藏的 `CSRF token`。

2. 如果是前后端分离，比如用 AJAX/axios/fetch 发送请求，需要做两件事：

    - 后端需要把 CSRF token 以某种方式（比如 cookie）暴露给前端。
    - 前端需要在每个需要保护的请求（比如 POST）中带上 token，通常在 X-CSRF-TOKEN 请求头里。

- 自定义 CSRF 配置（比如只对部分接口禁用）
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .ignoringRequestMatchers("/api/**") // 忽略CSRF保护的路径
        )
        .authorizeRequests()
            .anyRequest().authenticated()
        .and()
        .formLogin();
    return http.build();
}
```

### 参考资料

- https://www.cnblogs.com/Chary/p/18026736