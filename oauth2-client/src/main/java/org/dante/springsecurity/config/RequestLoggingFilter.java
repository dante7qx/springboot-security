package org.dante.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.util.Enumeration;

/**
 * 用于调试
 */
//@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class RequestLoggingFilter extends OncePerRequestFilter {

    @Override
    @SneakyThrows
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        String uri = request.getRequestURI();
        String queryString = request.getQueryString();

        log.info("Processing request: {} {}", request.getMethod(), request.getRequestURI());
        log.info("Context path: {}", request.getContextPath());
        log.info("Servlet path: {}", request.getServletPath());
        log.info("Query string: {}", request.getQueryString());

        // 特别记录OAuth2回调请求
        if (uri.contains("/login/oauth2/code/")) {
            log.info("OAuth2 callback detected!");
            log.info("Full URL: {}", request.getRequestURL().append(queryString != null ? "?" + queryString : ""));

            // 记录所有请求头
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                log.info("Header: {} = {}", headerName, request.getHeader(headerName));
            }
        }

        filterChain.doFilter(request, response);
    }
}
