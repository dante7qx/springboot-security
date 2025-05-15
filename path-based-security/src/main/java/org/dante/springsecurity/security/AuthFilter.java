package org.dante.springsecurity.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.dante.springsecurity.dao.UserDAO;
import org.dante.springsecurity.vo.UserVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
public class AuthFilter extends UsernamePasswordAuthenticationFilter {
	
	@Autowired
	private UserDAO userDAO;
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		if (!request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException(
					"Authentication method not supported: " + request.getMethod());
		}
		
		String username = obtainUsername(request);
		String password = obtainPassword(request);
		if (username == null) {
			throw new UsernameNotFoundException("用户名不能为空");
		}
		if (password == null) {
			throw new UsernameNotFoundException("密码不能为空");
		}
		log.info("开始对{}进行认证。。。", username);
		username = username.trim();
		UserVO userVO = userDAO.findUserByUsername(username);
		if(userVO == null) {
			throw new UsernameNotFoundException("用户名["+username+"]不存在！");
		}
		
		if(!new BCryptPasswordEncoder().matches(password, userVO.getPassword())) {
			throw new UsernameNotFoundException("密码错误");
		}
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, password);
		return this.getAuthenticationManager().authenticate(authRequest);
	}

}
