package org.dante.springsecurity.config;

import org.dante.springsecurity.security.AuthFilter;
import org.dante.springsecurity.security.AuthVoter;
import org.dante.springsecurity.security.AuthroizeSourceMetadata;
import org.dante.springsecurity.service.AuthService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collections;

/**
 * Spring Security5 必须要指定一个 PasswordEncoder
 * 
 * @author dante
 *
 */
@Configuration
@EnableWebSecurity
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
	public AuthFilter authFilter(AuthenticationManager authenticationManager) throws Exception {
		AuthFilter authFilter = new AuthFilter();
		authFilter.setAuthenticationManager(authenticationManager);
		authFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
		return authFilter;
	}

	@Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
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
        return new AffirmativeBased(Collections.singletonList(new AuthVoter()));
	}
	
	@Bean
	public FilterSecurityInterceptor filterSecurityInterceptor(AuthenticationManager authenticationManager) throws Exception {
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		filterSecurityInterceptor.setSecurityMetadataSource(securityMetadataSource());
		filterSecurityInterceptor.setAuthenticationManager(authenticationManager);
		filterSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
		filterSecurityInterceptor.setRejectPublicInvocations(false);
		return filterSecurityInterceptor;
	}
	
	public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthFilter authFilter, FilterSecurityInterceptor filterSecurityInterceptor) throws Exception {
		http
			.csrf().disable()
			.authorizeRequests(request -> {
				request.requestMatchers(new AntPathRequestMatcher("/favicon.ico"), new AntPathRequestMatcher("/home")).permitAll()
						.anyRequest().authenticated();
			})
			.formLogin()
			.and()
			.addFilterAt(authFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterAt(filterSecurityInterceptor, FilterSecurityInterceptor.class);
		return http.build();
	}
	
}
