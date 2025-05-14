package org.dante.springsecurity.controller;

import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.model.AuthRequest;
import org.dante.springsecurity.model.AuthResponse;
import org.dante.springsecurity.security.PBKDF2Encoder;
import org.dante.springsecurity.service.JWTUtil;
import org.dante.springsecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
public class AuthenticationController {

	private final JWTUtil jwtUtil;
	private final PBKDF2Encoder passwordEncoder;
	private final UserService userRepository;

	@PostMapping("/auth/login")
	public Mono<ResponseEntity<?>> login(@RequestBody AuthRequest ar) {
		return userRepository.findByUsername(ar.getUsername()).map(u -> {
			if (passwordEncoder.encode(ar.getPassword()).equals(u.getPassword())) {
				return ResponseEntity.ok(new AuthResponse(jwtUtil.generateToken(u)));
			} else {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
			}
		}).defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
	}

}
