package org.dante.springsecurity.config;

import static java.util.stream.Collectors.toSet;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.dante.springsecurity.security.MenuAuth;
import org.dante.springsecurity.vo.UserVO;
import org.springframework.http.HttpMethod;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class InitDataConfig {

	private static final List<UserVO> userVos;
	private static final Map<MenuAuth, String> menuConfigAttributes = new HashMap<>();
	
	public final static String PUBLIC_ACCESS = "PUBLIC_ACCESS";
	
	private final static String AUTH_USER_ADD = "AUTH_USER_ADD";
	private final static String AUTH_USER_DEL = "AUTH_USER_DEL";
	
	private final static String AUTH_MENU_ADD = "AUTH_MENU_ADD";
	private final static String AUTH_MENU_DEL = "AUTH_MENU_DEL";

	/**
	 * 初始化用户信息
	 */
	static {
		log.info("初始化用户信息......");
		userVos = Arrays.asList(
			new UserVO("dante", "$2a$10$yKyh2RWtar7eUrE9O.67M.NaYA8zpr3CgbBmm7L9V4G/7Ttx.hCf2", "super@163.com",
				Arrays.asList("足球", "编程", "音乐", "游戏"), 
				Stream.of(AUTH_USER_ADD, AUTH_USER_DEL, AUTH_MENU_ADD, AUTH_MENU_DEL).collect(toSet())),
			new UserVO("snake", "$2a$10$yKyh2RWtar7eUrE9O.67M.NaYA8zpr3CgbBmm7L9V4G/7Ttx.hCf2", "kid@163.com",
					Arrays.asList("足球", "编程", "音乐", "游戏"), 
					Stream.of(AUTH_USER_ADD, AUTH_USER_DEL).collect(toSet())),
			new UserVO("youna", "$2a$10$yKyh2RWtar7eUrE9O.67M.NaYA8zpr3CgbBmm7L9V4G/7Ttx.hCf2", "kid@163.com",
					Arrays.asList("足球", "编程", "音乐", "游戏"), 
					Stream.of(AUTH_MENU_ADD, AUTH_MENU_DEL).collect(toSet()))
		);
		
		log.info("初始化请求URL权限信息......");
		menuConfigAttributes.put(new MenuAuth("/user/add/**", HttpMethod.GET), AUTH_USER_ADD);
		menuConfigAttributes.put(new MenuAuth("/user/delete/**", HttpMethod.DELETE), AUTH_USER_DEL);
		menuConfigAttributes.put(new MenuAuth("/menu/add/**", HttpMethod.GET), AUTH_MENU_ADD);
		menuConfigAttributes.put(new MenuAuth("/menu/delete/**", HttpMethod.DELETE), AUTH_MENU_DEL);
	}

	public static List<UserVO> Users() {
		return userVos;
	}
	
	public static Map<MenuAuth, String> MenuConfigs() {
		return menuConfigAttributes;
	}
}