## 基于方法调用的认证鉴权

> 1. 配置类开启 `@EnableGlobalMethodSecurity(prePostEnabled = true)` 开启方法调用鉴权拦截
> 2. 使用`@PreAuthorize`配置访问接口需要的权限
> 3. 再从数据库中查询出用户所拥有的权限值设置到`UserDetails`对象

- InitDataConfig

 	模拟数据库中的用户数据和资源的权限配置。
- UserVO

  模拟用户数据表映射实体。

- AuthUser

  UserDetails 的具体实现，包含业务用户实体 UserVO。

- AuthService

  UserDetailsService 的具体实现，负责获取用户信息，并转化成 UserDetails，即 AuthUser。

- AuthFilter

  继承 UsernamePasswordAuthenticationFilter，实现具体的用户认证业务。

- 被调用方法

  在方法上添加注解 `@PreAuthorize("hasAuthority('AUTH_USER_DEL')")`

- 总配置

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

  private final AuthService authService;

  public SecurityConfig(AuthService authService) {
    this.authService = authService;
  }

  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
    authenticationProvider.setUserDetailsService(authService);
    authenticationProvider.setPasswordEncoder(passwordEncoder());
    return authenticationProvider;
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
    return configuration.getAuthenticationManager();
  }

  @Bean
  public SavedRequestAwareAuthenticationSuccessHandler authenticationSuccessHandler() {
    SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
    handler.setDefaultTargetUrl("/home");
    handler.setAlwaysUseDefaultTargetUrl(true);
    return handler;
  }

  @Bean
  public AuthFilter authFilter(AuthenticationManager authenticationManager) {
    AuthFilter authFilter = new AuthFilter();
    authFilter.setAuthenticationManager(authenticationManager);
    authFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
    return authFilter;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthFilter authFilter) throws Exception {
        /*
        AuthFilter authFilter = new AuthFilter();
        authFilter.setAuthenticationManager(authenticationManager);
        authFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        */
    http
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/favicon.ico", "/home").permitAll()
            .antMatchers("/*").authenticated()
            .and()
            .formLogin()
            .and()
            .addFilterAt(authFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }
}

/**
 * 2. 使用`@PreAuthorize`配置访问接口需要的权限
 */
@RestController
@RequestMapping("/menu")
public class MenuController {

  @GetMapping("/add/{menu}")
  @PreAuthorize("hasAuthority('" + InitDataConfig.AUTH_MENU_ADD + "')")
  public String addMenu(@PathVariable String menu) {
    return menu.concat("添加成功！");
  }

  @DeleteMapping("/delete/{menu}")
  @PreAuthorize("hasAuthority('" + InitDataConfig.AUTH_MENU_DEL + "')")
  public String delMenu(@PathVariable String menu) {
    return menu.concat("删除成功！");
  }

}

/**
 * 3. 再从数据库中查询出用户所拥有的权限值设置到`UserDetails`对象
 */
@Slf4j
@Service
public class AuthService implements UserDetailsService {

  private final UserDAO userDAO;

  public AuthService(UserDAO userDAO) {
    this.userDAO = userDAO;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserVO userVO = userDAO.findUserByUsername(username);
    if (userVO == null) {
      throw new UsernameNotFoundException(username + "在系统中不存在。");
    }
    log.info("{} 认证成功。", username);
    return new AuthUser(userVO);
  }

}
```

