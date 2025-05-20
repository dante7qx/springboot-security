package org.dante.springsecurity.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.dante.springsecurity.dao.UserDAO;
import org.dante.springsecurity.entity.SysUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserDAO userDAO;
    private final PasswordEncoder passwordEncoder;

    // 初始化一些测试用户
    @PostConstruct
    @Transactional
    public void initUsers() {
        log.info("===============================> 初始化用户...");
        if (!userDAO.existsByUsername("admin")) {
            createUser("admin", "123@qwe", "管理员", "admin@example.com", "13830291872", "ADMIN");
        }
        if (!userDAO.existsByUsername("snake")) {
            createUser("user", "123@qwe", "固体蛇", "user@example.com", "15271651122", "USER");
        }
        if (!userDAO.existsByUsername("dante")) {
            createUser("dante", "123@qwe", "但丁", "dante@example.com", "18911778877", "USER");
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userDAO.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("用户不存在: " + username));
    }

    @Transactional
    public void createUser(String username, String password, String nickname, String email, String phone, String role) {
        SysUser user = new SysUser();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setEmail(email);
        user.setPhone(phone);
        user.setNickname(nickname);
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