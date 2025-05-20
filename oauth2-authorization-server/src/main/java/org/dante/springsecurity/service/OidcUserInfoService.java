package org.dante.springsecurity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.dante.springsecurity.dao.UserDAO;
import org.dante.springsecurity.entity.SysUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static cn.hutool.core.util.ObjectUtil.isNull;

@Slf4j
@Service
@RequiredArgsConstructor
public class OidcUserInfoService {

    private final UserDAO userDAO;

    public OidcUserInfo loadUser(String username) {
        log.info("第三方客户端 SSO 登录认证成功，授权用户 {}", username);
        Map<String, Object> claims = userDAO.findByUsername(username).map(user -> {
            Map<String, Object> map = new HashMap<>();
            map.put("username", user.getUsername());
            map.put("nickname", user.getNickname());
            map.put("email", user.getEmail());
            map.put("phone", user.getPhone());
            return map;
        }).orElse(Map.of());

        return new OidcUserInfo(claims);
    }

    public OidcUserInfo loadUser(JwtAuthenticationToken principal) {
        if(isNull(principal)) {
            return null;
        }
        Map<String, Object> claims = new HashMap<>();
        String username = principal.getName();
        Set<String> authorizedScopes = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(auth -> auth.startsWith("SCOPE_"))
                .map(auth -> auth.substring("SCOPE_".length()))
                .collect(Collectors.toSet());

        log.info("第三方客户端 SSO 登录认证成功，授权用户 {} — {}", username, authorizedScopes);
        claims.put(StandardClaimNames.SUB, username);

        SysUser sysUser = userDAO.findByUsername(username).orElse(new SysUser());
        claims.put(StandardClaimNames.NICKNAME, sysUser.getNickname());

        if (authorizedScopes.contains(OidcScopes.PROFILE)) {
            claims.put(StandardClaimNames.PROFILE, "");
            claims.put(StandardClaimNames.NICKNAME, sysUser.getNickname());
        }

        if (authorizedScopes.contains(OidcScopes.EMAIL)) {
            claims.put(StandardClaimNames.EMAIL, sysUser.getEmail());
        }

        if (authorizedScopes.contains(OidcScopes.PHONE)) {
            claims.put(StandardClaimNames.PHONE_NUMBER, sysUser.getPhone());
        }

        return new OidcUserInfo(claims);
    }
}
