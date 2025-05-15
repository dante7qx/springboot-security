package org.dante.springsecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 自定义异常处理器
 * 捕获访问受保护资源时发生的异常，并根据具体情况触发适当的认证或授权流程。
 * 当用户尝试访问受保护资源但未经过身份验证时，ExceptionTranslationFilter 会调用 身份验证入口 (AuthenticationEntryPoint) 来启动认证流程
 *    1. 如果是未认证用户访问受保护资源，它会触发登录或重定向到授权页面。
 *    2. 如果是认证用户但权限不足，它可能返回 403 Forbidden。
 *    3. 结合 OAuth2，它可能引导用户进入授权流程，比如跳转到 OAuth2 认证服务器。
 */
public class SpiritAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, String> errorDetails = new HashMap<>();
        errorDetails.put("error", "unauthorized");
        errorDetails.put("error_desc", "“需要完整身份验证才能访问此资源");
        errorDetails.put("message", authException.getMessage());

        objectMapper.writeValue(response.getWriter(), errorDetails);
    }
}
