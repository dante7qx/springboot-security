package org.dante.springsecurity;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class PasswordEncoderTests {

	@Test
	public void encode() {
		log.info(new BCryptPasswordEncoder().encode("123456"));
	}
	
}
