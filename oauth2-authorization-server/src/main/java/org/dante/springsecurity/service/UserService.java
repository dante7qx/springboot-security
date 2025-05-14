package org.dante.springsecurity.service;

import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.dao.UserDAO;
import org.dante.springsecurity.entity.SysUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import java.util.Collections;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserDAO userDAO;
    private final PasswordEncoder passwordEncoder;

    // 初始化一些测试用户
    @PostConstruct
    @Transactional
    public void initUsers() {
        if (!userDAO.existsByUsername("admin")) {
            createUser("admin", "1qa@2ws", "admin@example.com", "ADMIN");
        }
        if (!userDAO.existsByUsername("snake")) {
            createUser("user", "1qa@2ws", "user@example.com", "USER");
        }
        if (!userDAO.existsByUsername("dante")) {
            createUser("dante", "iamdante", "dante@example.com", "USER");
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDAO.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("用户不存在: " + username));
    }

    @Transactional
    public void createUser(String username, String password, String email, String role) {
        SysUser user = new SysUser();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setEmail(email);
        user.setRoles(Collections.singleton(role));
        userDAO.save(user);
    }

    public Optional<SysUser> findByUsername(String username) {
        return userDAO.findByUsername(username);
    }

    public boolean existsByUsername(String username) {
        return userDAO.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userDAO.existsByEmail(email);
    }


}