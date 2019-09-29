package org.dante.springsecurity.service;

import java.util.Arrays;

import org.dante.springsecurity.model.Role;
import org.dante.springsecurity.model.User;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Mono;

@Service
public class UserService {

	// username:passwowrd -> user:user
	private final String userUsername = "user"; // password: user
	private final User user = new User(userUsername, "cBrlgyL2GI2GINuLUUwgojITuIufFycpLG4490dhGtY=", true,
			Arrays.asList(Role.ROLE_USER));

	// username:passwowrd -> admin:admin
	private final String adminUsername = "admin";// password: admin
	private final User admin = new User(adminUsername, "dQNjUIMorJb8Ubj2+wVGYp6eAeYkdekqAcnYp+aRq5w=", true,
			Arrays.asList(Role.ROLE_ADMIN));

	public Mono<User> findByUsername(String username) {
		if (username.equals(userUsername)) {
			return Mono.just(user);
		} else if (username.equals(adminUsername)) {
			return Mono.just(admin);
		} else {
			return Mono.empty();
		}
	}

}
