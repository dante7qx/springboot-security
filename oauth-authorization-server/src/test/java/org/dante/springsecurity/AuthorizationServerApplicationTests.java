package org.dante.springsecurity;

import cn.hutool.core.lang.Console;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class AuthorizationServerApplicationTests {

    @Test
    void bcrypt() {
        var encoder = new BCryptPasswordEncoder();
        Console.log(encoder.encode("client-secret"));
    }
}
