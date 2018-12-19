package org.dante.springsecurity.dao;

import org.dante.springsecurity.config.InitDataConfig;
import org.dante.springsecurity.vo.UserVO;
import org.springframework.stereotype.Repository;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Repository
public class UserDAO {
	
	public UserVO findUserByUsername(String username) {
		log.info("开始从数据库中获取用户信息 {}", username);
		int index = InitDataConfig.Users().indexOf(new UserVO(username));
		if(index < 0) {
			return null;
		}
		return InitDataConfig.Users().get(index);
	}
	
}
