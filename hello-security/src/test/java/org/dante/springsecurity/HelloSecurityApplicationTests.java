package org.dante.springsecurity;

import cn.hutool.core.lang.Console;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class HelloSecurityApplicationTests {

    @Test
    void testPasswordEncoder() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

        String rawPassword = "123@qwe";
        String encodedPassword = encoder.encode(rawPassword);
        Console.log("Password -> {}", encodedPassword);
        Assertions.assertTrue(encoder.matches(rawPassword, encodedPassword));
        Assertions.assertTrue(encodedPassword.startsWith("{bcrypt}"));
    }
}
