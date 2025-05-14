## OAuth2 客户端

通过 `spring-security-oauth2-client` 实现客户端应用（如Web应用或移动端）的`OAuth 2.0`登录和资源访问功能。

1. **添加依赖**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-client</artifactId>
</dependency>
<!-- 解析 JWT Token -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<!-- 可选，用于使用 WebClient -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-webflux</artifactId>
</dependency>
<!-- 其他依赖 -->
```

2. **配置授权服务器**
```yaml
server:
  port: 8003
  servlet:
    context-path: /client

spring:
  security:
    oauth2:
      client:
        registration:                                                     # ClientRegistration 已在授权服务器注册的客户端，自动注入为一个 ClientRegistration Bean
          secret-basic-client:                                            # registrationId 同 ClientId
            client-id: secret-basic-client
            client-secret: secret-basic-secret
            client-name: "Spirit 客户端"
            authorization-grant-type: authorization_code                  # authorization_code, client_credentials, password, urn:ietf:params:oauth:grant-type:jwt-bearer
            scope: api.book.read,api.book.write
            client-authentication-method: client_secret_basic             # client_secret_basic, client_secret_post, private_key_jwt, client_secret_jwt and none
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"  # 固定格式
            provider: spirit-provider                                     # 关联的授权服务器配置
        provider:
          spirit-provider:
            authorization-uri: ${spirit.auth-server-url}/oauth2/authorize   # 授权服务器的授权 Endpoint
            token-uri: ${spirit.auth-server-url}/oauth2/token               # 授权服务器的令牌 Endpoint
            jwk-set-uri: ${spirit.auth-server-url}/oauth2/jwks             # 公钥地址
            # 无 issuer-uri 和 user-info-uri（只使用 OAuth2，无 OIDC）
spirit:
  auth-server-url: http://localhost:8001          # 授权服务器地址
  resource-server-url: http://localhost:8002      # 资源服务器地址
```

3. **安全配置**

    <details>
         <summary>SecurityConfig.java</summary>
   
    ```java
    @Configuration
    @RequiredArgsConstructor
    public class SecurityConfig {
        
        private final SpiritOAuth2UserService oAuth2UserService;
    
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                .authorizeRequests(authorize -> authorize
                    .antMatchers("/", "/login", "/error").permitAll()
                    .antMatchers("/css/**", "/js/**").permitAll()
                    .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                    .loginPage("/login")
                    .defaultSuccessUrl("/home", true)
                    .failureUrl("/login?error=true")
                    // 避免调用默认的 userInfoUri（坑点）
                    .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                )
                .logout(logout -> logout
                    .logoutSuccessUrl("/")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                );
    
            return http.build();
        }
    
        @Bean
        public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRepo, OAuth2AuthorizedClientRepository authorizedClientRepo) {
            OAuth2AuthorizedClientProvider clientProvider =
                    OAuth2AuthorizedClientProviderBuilder.builder()
                            .authorizationCode()
                            .refreshToken()
                            .clientCredentials()
                            .build();
            DefaultOAuth2AuthorizedClientManager clientManager = new DefaultOAuth2AuthorizedClientManager(clientRepo, authorizedClientRepo);
            clientManager.setAuthorizedClientProvider(clientProvider);
            return clientManager;
        }
    
    }
    ```
    </details>


4. 自定义的 OAuth2UserService

   Spring Security 的 DefaultOAuth2UserService 默认用于 OpenID Connect (OIDC) 或 具有用户信息端点的 OAuth2 提供者，
   它期望 user-info-uri 被设置（从该地址拉取用户详细信息）。但只是使用 OAuth2 授权码模式，没有配置 OIDC，也没有 user-info-uri。所以，若只有
   `OAuth2` 认证，则改为使用 JWT 的 Principal 提取方式（推荐，纯 OAuth2）
   

   <details>
      <summary>SpiritOAuth2UserService.java</summary>
   
   ```java
   @Service
   public class SpiritOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
   
       private final static String NAME_ATTRIBUTE_KEY = "name";
   
       // TODO: 目前只支持 JWT，后续考虑支持不同类型 token（opaque、JWT 混合场景）
       @Override
       public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
           String tokenValue = userRequest.getAccessToken().getTokenValue();
           Map<String, Object> claims;
   
           try {
               SignedJWT signedJWT = (SignedJWT) JWTParser.parse(tokenValue);
               claims = new HashMap<>(signedJWT.getJWTClaimsSet().getClaims());
           } catch (ParseException e) {
               throw new IllegalArgumentException("无法解析JWT", e);
           }
   
           // 提取权限
           Collection<SimpleGrantedAuthority> scopes = new ArrayList<>();
           Object scope = claims.get("scope");
           if (scope instanceof List<?>) {
               ((List<?>) scope).forEach(auth -> scopes.add(new SimpleGrantedAuthority(auth.toString())));
           }
   
           // 提取用户名
           String name = (String) claims.getOrDefault("sub", "unknown");
           claims.put(NAME_ATTRIBUTE_KEY, name);
   
           return new DefaultOAuth2User(scopes, claims, NAME_ATTRIBUTE_KEY);
       }
   }
   ```

</details>


5. **登录页**
```html
<div class="d-grid gap-2 mb-3">
   <a class="btn btn-primary" th:href="@{/oauth2/authorization/secret-basic-client}">
       使用OAuth2登录
   </a>
</div>
```

`/client/oauth2/authorization/secret-basic-client` 是 `Spring Security OAuth2 Client`的一个特定格式的`URL`

格式: `<context-path>/oauth2/authorization/<registrationId>`

流程: 
   1. Spring Security截获这个请求，识别出这是一个OAuth2授权请求
   2. 从URL中提取客户端注册ID
   3. 使用这个ID 在 yml 中查找相应的客户端配置 
   4. 构建重定向URL，将用户重定向到授权服务器的 AuthorizationEndpoint
   5. 在重定向URL中包含必要的参数（clientId、redirectUri、scope等）
   6. 自定义
   ```java
   .oauth2Login(oauth2 -> oauth2
         .authorizationEndpoint(authorization -> authorization
             .baseUri("/custom-oauth2/authorize")  // 自定义授权端点基础路径
         )
    );
   ```


6. **获取资源服务器数据**

- (1) WebClient 配置
```java
/**
 * 创建一个支持 OAuth2 认证的 WebClient 实例
 */
@Configuration
public class WebClientConfig {
    @Bean
    public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
                new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

        return WebClient.builder()
                .apply(oauth2Client.oauth2Configuration())
                .build();
    }
}
```
- (2) 请求资源API
```java
@GetMapping("/resource")
 public String getResource(@RegisteredOAuth2AuthorizedClient("secret-basic-client") OAuth2AuthorizedClient authorizedClient, Model model) {
     // 使用访问令牌调用资源服务器
     String resourceResponse = webClient
          .get()
          .uri(spiritClientProp.getResourceServerUrl()+ "/api/book/200") // 资源服务器的API地址
          .attributes(oauth2AuthorizedClient(authorizedClient))
          .retrieve()
          .bodyToMono(String.class)
          .block();

     model.addAttribute("resourceResponse", resourceResponse);
     return "resource";
 }
```

