package org.dante.springsecurity.exception;

import lombok.Data;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Data
public class ResourceNotFoundException extends RuntimeException {
    private String resourceType;
    private String resourceId;
    private String errorCode;
    private Instant timestamp;
    private String requestId;
    private final Map<String, Object> additionalInfo;

    /**
     * 创建ResourceNotFoundException的构造函数
     *
     * @param resourceType 资源类型（如user, client, token等）
     * @param resourceId 资源标识符
     * @param errorCode 错误代码
     * @param message 错误消息
     * @param requestId 当前请求的唯一标识符
     */
    public ResourceNotFoundException(String resourceType, String resourceId,
                                     String errorCode, String message, String requestId) {
        super(message);
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.errorCode = errorCode;
        this.timestamp = Instant.now();
        this.requestId = requestId;
        this.additionalInfo = new HashMap<>();
    }

    /**
     * 简化的构造函数
     */
    public ResourceNotFoundException(String resourceType, String resourceId, String errorCode) {
        this(resourceType, resourceId, errorCode,
                String.format("Resource of type '%s' with identifier '%s' was not found", resourceType, resourceId),
                generateRequestId());
    }

    /**
     * 添加附加信息到异常对象
     *
     * @param key 信息键
     * @param value 信息值
     * @return 当前异常实例，支持链式调用
     */
    public ResourceNotFoundException addInfo(String key, Object value) {
        this.additionalInfo.put(key, value);
        return this;
    }

    // 静态工厂方法，用于创建特定资源类型的异常

    /**
     * 创建用户不存在异常
     *
     * @param userId 用户ID
     * @return 异常实例
     */
    public static ResourceNotFoundException userNotFound(String userId) {
        return new ResourceNotFoundException("user", userId, "USER_404",
                "User not found with ID: " + userId,
                generateRequestId());
    }

    /**
     * 创建客户端应用不存在异常
     *
     * @param clientId 客户端ID
     * @return 异常实例
     */
    public static ResourceNotFoundException clientNotFound(String clientId) {
        return new ResourceNotFoundException("client", clientId, "CLIENT_404",
                "Client application not found with ID: " + clientId,
                generateRequestId());
    }

    /**
     * 创建访问令牌不存在异常
     *
     * @param tokenId 令牌ID
     * @return 异常实例
     */
    public static ResourceNotFoundException tokenNotFound(String tokenId) {
        return new ResourceNotFoundException("token", tokenId, "TOKEN_404",
                "Access token not found or expired: " + tokenId,
                generateRequestId());
    }

    /**
     * 创建授权记录不存在异常
     *
     * @param authId 授权ID
     * @return 异常实例
     */
    public static ResourceNotFoundException authorizationNotFound(String authId) {
        return new ResourceNotFoundException("authorization", authId, "AUTH_404",
                "Authorization record not found with ID: " + authId,
                generateRequestId());
    }

    /**
     * 创建作用域不存在异常
     *
     * @param scopeName 作用域名称
     * @return 异常实例
     */
    public static ResourceNotFoundException scopeNotFound(String scopeName) {
        return new ResourceNotFoundException("scope", scopeName, "SCOPE_404",
                "Requested scope not found: " + scopeName,
                generateRequestId());
    }

    // 生成请求ID的简单实现
    private static String generateRequestId() {
        return "req-" + System.currentTimeMillis() + "-" + Math.abs(java.util.UUID.randomUUID().getLeastSignificantBits() % 1000);
    }

    /**
     * 将异常转换为可用于HTTP响应的错误Map
     *
     * @return 包含所有异常信息的Map
     */
    public Map<String, Object> toErrorResponse() {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "resource_not_found");
        errorResponse.put("error_description", getMessage());
        errorResponse.put("resource_type", resourceType);
        errorResponse.put("resource_id", resourceId);
        errorResponse.put("error_code", errorCode);
        errorResponse.put("timestamp", timestamp.toString());
        errorResponse.put("request_id", requestId);

        // 添加其他信息
        if (!additionalInfo.isEmpty()) {
            errorResponse.put("additional_info", additionalInfo);
        }

        return errorResponse;
    }

    @Override
    public String toString() {
        return String.format("ResourceNotFoundException[type=%s, id=%s, code=%s, requestId=%s, message=%s]",
                resourceType, resourceId, errorCode, requestId, getMessage());
    }
}
