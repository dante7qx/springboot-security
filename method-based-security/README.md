## 基于方法调用的认证鉴权

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
/** 
 * @EnableGlobalMethodSecurity(prePostEnabled = true) 开启方法调用鉴权拦截
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private AuthService authService;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthFilter authFilter() throws Exception {
		AuthFilter authFilter = new AuthFilter();
		authFilter.setAuthenticationManager(authenticationManagerBean());
		authFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
		return authFilter;
	}
	
	@Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
	
	@Bean
	public SavedRequestAwareAuthenticationSuccessHandler authenticationSuccessHandler() {
		SavedRequestAwareAuthenticationSuccessHandler authenticationSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		authenticationSuccessHandler.setDefaultTargetUrl("/home");
		authenticationSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
		return authenticationSuccessHandler;
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider =  new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(authService);
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		return authenticationProvider;
	}
	
	@Autowired
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests().antMatchers("/favicon.ico","/home").permitAll()
			.and()
			.addFilterAt(authFilter(), UsernamePasswordAuthenticationFilter.class);
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}
	
}
```

