package org.dante.springsecurity.security;

import java.util.Collection;
import java.util.Set;

import org.dante.springsecurity.config.InitDataConfig;
import org.dante.springsecurity.vo.UserVO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import lombok.Data;

@Data
public class AuthUser implements UserDetails {
	
	private static final long serialVersionUID = 1L;
	
	private UserVO user;
	
	public AuthUser() {
		
	}
	
	public AuthUser(UserVO user) {
		this.user = user;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Set<String> authoritys = this.user.getAuthCodes();
		if (!CollectionUtils.isEmpty(authoritys)) {
			authoritys.add(InitDataConfig.PUBLIC_ACCESS);
			return AuthorityUtils.createAuthorityList(authoritys.toArray(new String[authoritys.size()]));
		}
		return null;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}
