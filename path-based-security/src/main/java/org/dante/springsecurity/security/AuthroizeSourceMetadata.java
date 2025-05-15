package org.dante.springsecurity.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.dante.springsecurity.config.InitDataConfig;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * 动态权限数据源，用于获取动态权限规则
 */
@Slf4j
public class AuthroizeSourceMetadata implements FilterInvocationSecurityMetadataSource {

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		final HttpServletRequest request = ((FilterInvocation) object).getRequest();
		Map<MenuAuth, String> menuConfigAttributes = InitDataConfig.MenuConfigs();
		log.info("开始获取请求 {} 对应的权限码...", request.getRequestURI());
		for(Map.Entry<MenuAuth, String> entry : menuConfigAttributes.entrySet()) {
			MenuAuth menuAuth = entry.getKey();
			if(new AntPathRequestMatcher(menuAuth.getPattern(), menuAuth.getMethod().name()).matches(request)) {
				return List.of(new SecurityConfig(entry.getValue()));
			}
		}
		return List.of(new SecurityConfig(InitDataConfig.PUBLIC_ACCESS));
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		/*
		Set<ConfigAttribute> allAttributes = new HashSet<>();
		Map<MenuAuth, String> menuConfigAttributes = InitDataConfig.MenuConfigs();
		for(Map.Entry<MenuAuth, String> entry : menuConfigAttributes.entrySet()) {
			allAttributes.add(new SecurityConfig(entry.getValue()));
		}
		return allAttributes;
		*/
		return null;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

}
