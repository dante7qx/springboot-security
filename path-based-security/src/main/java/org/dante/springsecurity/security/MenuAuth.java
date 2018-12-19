package org.dante.springsecurity.security;

import org.springframework.http.HttpMethod;
import org.springframework.util.ObjectUtils;

import lombok.Data;

@Data
public class MenuAuth {
	private String pattern;
	private HttpMethod method;
	
	public MenuAuth(String pattern, HttpMethod method) {
		this.pattern = pattern;
		this.method = method;
	}
	
	@Override
	public boolean equals(Object obj) {
		MenuAuth ma = (MenuAuth) obj;
		return ma == null ? false : pattern.equalsIgnoreCase(ma.getPattern());
	}
	
	@Override
	public int hashCode() {
		return ObjectUtils.nullSafeHashCode(pattern);
	}
}
