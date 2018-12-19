## 基于请求 URL 的认证授权

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

- AuthroizeSourceMetadata

  FilterInvocationSecurityMetadataSource 的具体实现，用于获取请求URL对应的权限信息。

- AuthVoter

  自定义投票器，仿照 RoleVoter 编写。

- 总配置

```java
@EnableWebSecurity
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
	
	@Bean
	public FilterInvocationSecurityMetadataSource securityMetadataSource() {
		return new AuthroizeSourceMetadata();
	}
	
	@Bean 
	public AccessDecisionManager accessDecisionManager() {
		AccessDecisionManager accessDecisionManager = new AffirmativeBased(Arrays.asList(new AuthVoter()));
		return accessDecisionManager;
	}
	
	@Bean
	public FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		filterSecurityInterceptor.setSecurityMetadataSource(securityMetadataSource());
		filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
		filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
		filterSecurityInterceptor.setRejectPublicInvocations(false);
		return filterSecurityInterceptor;
	}
	
	@Autowired
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
		http
			.authorizeRequests().antMatchers("/favicon.ico","/home").permitAll()
			.and()
			.addFilterAt(authFilter(), UsernamePasswordAuthenticationFilter.class)
			.addFilterAt(filterSecurityInterceptor(), FilterSecurityInterceptor.class);
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}
	
}
```

