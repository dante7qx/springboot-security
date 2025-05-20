package org.dante.springsecurity.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 本地调试，生产环境不推荐自定义 OidcLogoutSuccessHandler
 * 自定义一个 OidcLogoutSuccessHandler, 处理 oidcLogoutEndpoint 的逻辑
 * 参考 org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler
 */
@Slf4j
public final class SpiritOidcLogoutHandler implements AuthenticationSuccessHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
    private LogoutHandler logoutHandler = this::performLogout;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 解析参数
        String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");
        String state = request.getParameter("state");

        // 做你想做的：日志、清理token、会话等
        log.info("RP logout: redirectUri={}, state={}, user={}", postLogoutRedirectUri, state, authentication != null ? authentication.getName() : "N/A");
        if (!(authentication instanceof OidcLogoutAuthenticationToken)) {
            assert authentication != null;
            log.error("{} must be of type {} but was {}", Authentication.class.getSimpleName(), OidcLogoutAuthenticationToken.class.getName(), authentication.getClass().getName());
            OAuth2Error error = new OAuth2Error("server_error", "Unable to process the OpenID Connect 1.0 RP-Initiated Logout response.", "");
            throw new OAuth2AuthenticationException(error);
        } else {
            // 清理 session 和登录状态
            request.logout();
            this.logoutHandler.logout(request, response, authentication);
            this.sendLogoutRedirect(request, response, authentication);
        }
    }

    public void setLogoutHandler(LogoutHandler logoutHandler) {
        Assert.notNull(logoutHandler, "logoutHandler cannot be null");
        this.logoutHandler = logoutHandler;
    }

    private void performLogout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken)authentication;
        if (oidcLogoutAuthentication.isPrincipalAuthenticated()) {
            this.securityContextLogoutHandler.logout(request, response, (Authentication)oidcLogoutAuthentication.getPrincipal());
        }

    }

    private void sendLogoutRedirect(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken)authentication;
        String redirectUri = "/";
        if (oidcLogoutAuthentication.isAuthenticated() && StringUtils.hasText(oidcLogoutAuthentication.getPostLogoutRedirectUri())) {
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(oidcLogoutAuthentication.getPostLogoutRedirectUri());
            if (StringUtils.hasText(oidcLogoutAuthentication.getState())) {
                uriBuilder.queryParam("state", new Object[]{UriUtils.encode(oidcLogoutAuthentication.getState(), StandardCharsets.UTF_8)});
            }

            redirectUri = uriBuilder.build(true).toUriString();
        }

        this.redirectStrategy.sendRedirect(request, response, redirectUri);
    }

}
