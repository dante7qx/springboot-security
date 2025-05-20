package org.dante.springsecurity.controller;

import cn.hutool.core.util.StrUtil;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.text.ParseException;

/**
 * OIDC 注销 AS 中的登录会话
 * 处理 oidcLogoutEndpoint("/connect/logout")
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class OidcLogoutController {

    private final JwtDecoder jwtDecoder;

    @SneakyThrows
    @GetMapping("/connect/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication,
                         @RequestParam(name = "id_token_hint", required = false) String idTokenHint,
                         @RequestParam(name = "post_logout_redirect_uri", required = false) String redirectUri,
                         @RequestParam(name = "state", required = false) String state,
                         Model model) {

        log.info("OIDC Logout requested. post_logout_redirect_uri: {}, state: {}", redirectUri, state);

        if(StrUtil.isNotEmpty(idTokenHint)) {
            // 验证 id_token_hint
            try {
                JWT jwt = JWTParser.parse(idTokenHint);

                if (jwt instanceof SignedJWT) {
                    // 使用 Spring Security 的 JwtDecoder 验证签名、过期等
                    Jwt decoded = jwtDecoder.decode(idTokenHint);
                    log.info("Decoded id_token_hint subject: {}", decoded.getSubject());
                    // 可以进一步做身份匹配、客户端校验等
                } else {
                    log.warn("Invalid id_token_hint (not signed)");
                    model.addAttribute("error", "Invalid id_token_hint (not signed).");
                }
            } catch (ParseException e) {
                log.warn("Failed to parse id_token_hint", e);
                model.addAttribute("error", "Failed to parse id_token_hint.");
            } catch (Exception e) {
                log.warn("Invalid or expired id_token_hint", e);
                model.addAttribute("error", "Invalid or expired id_token_hint.");
            }
        }

        // 清理 session 和登录状态
        request.logout();

        // 构造重定向地址
        String target = "/";
        if (StrUtil.isNotEmpty(redirectUri)) {
            target = redirectUri;
            if (StrUtil.isNotEmpty(state)) {
                target += (redirectUri.contains("?") ? "&" : "?") + "state=" + state;
            }
        }

        return "redirect:" + target;
    }
}
