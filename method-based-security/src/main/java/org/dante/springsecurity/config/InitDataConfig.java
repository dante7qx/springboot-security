package org.dante.springsecurity.config;

import static java.util.stream.Collectors.toSet;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.dante.springsecurity.vo.UserVO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class InitDataConfig {

	private static List<UserVO> userVos;
	
	public final static String PUBLIC_ACCESS = "PUBLIC_ACCESS";
	
	public final static String AUTH_USER_ADD = "AUTH_USER_ADD";
	public final static String AUTH_USER_DEL = "AUTH_USER_DEL";
	
	public final static String AUTH_MENU_ADD = "AUTH_MENU_ADD";
	public final static String AUTH_MENU_DEL = "AUTH_MENU_DEL";

	/**
	 * 初始化用户信息
	 */
	static {
		log.info("初始化用户信息......");
		userVos = Arrays.asList(
			new UserVO("dante", "$2a$10$mcclb9HF52oCZXI4XZERIuTl0qU/0jpFcvP7lZHH.pWSaRLKX3PXK", "super@163.com",
				Arrays.asList("足球", "编程", "音乐", "游戏"), 
				Stream.of(AUTH_USER_ADD, AUTH_USER_DEL, AUTH_MENU_ADD, AUTH_MENU_DEL).collect(toSet())),
			new UserVO("snake", "$2a$10$mcclb9HF52oCZXI4XZERIuTl0qU/0jpFcvP7lZHH.pWSaRLKX3PXK", "kid@163.com",
					Arrays.asList("足球", "编程", "音乐", "游戏"), 
					Stream.of(AUTH_USER_ADD, AUTH_USER_DEL).collect(toSet())),
			new UserVO("youna", "$2a$10$mcclb9HF52oCZXI4XZERIuTl0qU/0jpFcvP7lZHH.pWSaRLKX3PXK", "kid@163.com",
					Arrays.asList("足球", "编程", "音乐", "游戏"), 
					Stream.of(AUTH_MENU_ADD, AUTH_MENU_DEL).collect(toSet()))
		);
	}

	public static List<UserVO> Users() {
		return userVos;
	}
	
}