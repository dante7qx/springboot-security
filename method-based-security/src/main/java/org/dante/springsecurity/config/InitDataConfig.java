package org.dante.springsecurity.config;

import static java.util.stream.Collectors.toSet;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import jakarta.annotation.PostConstruct;
import org.dante.springsecurity.vo.UserVO;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class InitDataConfig {

	private static List<UserVO> userVos;
	
	public final static String PUBLIC_ACCESS = "PUBLIC_ACCESS";
	
	public final static String AUTH_USER_ADD = "AUTH_USER_ADD";
	public final static String AUTH_USER_DEL = "AUTH_USER_DEL";
	
	public final static String AUTH_MENU_ADD = "AUTH_MENU_ADD";
	public final static String AUTH_MENU_DEL = "AUTH_MENU_DEL";

	/*
	 * 初始化用户信息
	 */
	@PostConstruct
	public void init() {
		log.info("初始化用户信息......");
		userVos = Arrays.asList(
				new UserVO("dante", "{bcrypt}$2a$10$s0Ta/mltqMGKzSNnpPGBqOyGtNtz4khC/N4r4NBtGwoF7i5xxSOTu", "super@163.com",
						Arrays.asList("足球", "编程", "音乐", "游戏"),
						Stream.of(AUTH_USER_ADD, AUTH_USER_DEL, AUTH_MENU_ADD, AUTH_MENU_DEL).collect(toSet())),
				new UserVO("snake", "{bcrypt}$2a$10$s0Ta/mltqMGKzSNnpPGBqOyGtNtz4khC/N4r4NBtGwoF7i5xxSOTu", "kid@163.com",
						Arrays.asList("足球", "编程", "音乐", "游戏"),
						Stream.of(AUTH_USER_ADD, AUTH_USER_DEL).collect(toSet())),
				new UserVO("youna", "{bcrypt}$2a$10$s0Ta/mltqMGKzSNnpPGBqOyGtNtz4khC/N4r4NBtGwoF7i5xxSOTu", "kid@163.com",
						Arrays.asList("足球", "编程", "音乐", "游戏"),
						Stream.of(AUTH_MENU_ADD, AUTH_MENU_DEL).collect(toSet()))
		);
	}

	public static List<UserVO> Users() {
		return userVos;
	}
	
}