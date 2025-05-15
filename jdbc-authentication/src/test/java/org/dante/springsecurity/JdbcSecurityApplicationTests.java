package org.dante.springsecurity;

import cn.hutool.core.lang.Console;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class JdbcSecurityApplicationTests {

    @Autowired
    private JdbcUserDetailsManager userDetailsManager;

    @Test
    void testUserExists() {
        assertTrue(userDetailsManager.userExists("dante"));
        UserDetails user = userDetailsManager.loadUserByUsername("dante");
        Console.log("UserDetails => {}", user);
        assertNotNull(user);
        assertEquals(1, user.getAuthorities().size());
    }

}
