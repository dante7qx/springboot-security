package org.dante.springsecurity.service;

import org.dante.springsecurity.dao.UserDAO;
import org.dante.springsecurity.security.AuthUser;
import org.dante.springsecurity.vo.UserVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

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
		if(userVO == null) {
			throw new UsernameNotFoundException(username + "在系统中不存在。");
		}
		log.info("{} 认证成功。", username);
		return new AuthUser(userVO);
	}

}
