## Spring OAuth2 授权服务器

| 功能          | 资源服务器                                        | 授权服务器                                     |
|-------------|----------------------------------------------|-------------------------------------------|
| 核心职责        | 保护资源，验证访问令牌的合法性                              | 颁发访问令牌，管理客户端和用户的认证与授权                     |
| 依赖关系        | 依赖授权服务器提供令牌验证支持（如公钥）                         | 独立运行，提供令牌签发和验证端点（如 /oauth2/token）         |
| 典型实现        | `Spring Security + oauth2-resource-server`   | `Spring Authorization Server`、`Keycloak`、`Okta` |

### 一. 概述
OAuth2是一种授权框架，允许第三方应用获取对用户账户的有限访问权限，而无需获取用户的凭证。授权服务器是OAuth2体系中的核心组件，负责验证用户身份并颁发访问令牌。

**核心功能**

1. 用户认证：验证资源所有者(用户)的身份
2. 颁发授权码和访问令牌：根据不同的授权流程生成相应的令牌
3. 管理客户端应用注册：维护可信任的第三方应用列表
4. 支持多种授权模式：授权码模式、隐式授权、客户端凭证、资源所有者密码凭证等
5. 令牌管理：包括令牌的创建、校验、刷新和撤销

**Spring OAuth2 Authorization Server**

Spring生态系统中专门用于构建`OAuth2.0`和`OpenID Connect 1.0`授权服务器的框架。

1. `OAuth2`核心规范支持
   - 完整支持`OAuth2.0`框架(RFC6749)
   - 支持所有标准授权类型：授权码、客户端凭证、资源所有者密码凭证等
   - 支持令牌撤销(RFC7009)和令牌内省(RFC7662)

2. `OpenID Connect`支持
   - 支持`OpenID Connect Core 1.0`
   - 支持IdToken、UserInfo Endpoint
   - 支持标准 Claims

3. 安全增强
   - 支持`PKCE(Proof Key for Code Exchange)`增强授权码流程安全性
   - 支持`JWT(JSON Web Token)`格式的令牌
   - 支持资源服务器JWT验证

4. 客户端管理
   - 提供客户端注册和管理API
   - 支持动态客户端注册(DCR)
   - 灵活的客户端认证方式

5. 可扩展性
   - 提供多种扩展点和自定义选项
   - 可与Spring Security无缝集成
   - 支持自定义授权和令牌服务
6. 高级功能
   - 支持设备授权流程(Device Flow)
   - 支持令牌交换(Token Exchange)
   - 支持FAPI(Financial-grade API)安全配置文件
   - 提供全面的审计日志功能

**OpenID Connect（OIDC）**

1. 身份认证协议

- OpenID：主要提供用户身份认证功能，允许用户使用一个身份标识登录多个网站。

- OIDC：在OpenID的基础上增加了身份信息交换功能，除了认证用户身份，还可以获取用户的身份信息（如姓名、邮箱等）。

在OAuth 2.0基础上增加了身份验证功能，用于确认用户身份并提供基本的用户信息。引入了身份令牌（ID Token），包含用户身份信息，采用JWT格式。

2. 主要使用场景

- 需要用户身份认证的场景，如单点登录（SSO），用户登录一次即可访问多个应用

- 需要获取用户基本信息的场景，如社交登录，用户使用社交账号登录第三方应用。


### 二. 功能实现

[代码地址](https://github.com/dante7qx/springboot-security/tree/2.7.x)

1. **创建`Springboot`项目**
```xml
<parent>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-parent</artifactId>
     <version>3.4.5</version>
     <relativePath/> <!-- lookup parent from repository -->
</parent>
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<!-- 授权服务器 -->
<dependency>
   <groupId>org.springframework.security</groupId>
   <artifactId>spring-security-oauth2-authorization-server</artifactId>
   <version>1.4.3</version>
</dependency>
```

2. **动态客户端注册**
- **创建表存储客户端信息**
  <br>
   <details>
     <summary>oauth2_client.sql</summary>
  
   ```sql
   -- 1. 主客户端表
   create table oauth2_client
   (
       id                       varchar(36) primary key,
       client_id                varchar(100) not null unique,
       client_secret            varchar(256) not null,
       issued_at                date,
       expires_at               date
   );
   
   -- 2. 客户端认证方式表
   create table oauth2_client_auth_method
   (
       id        varchar(36) primary key,
       client_id varchar(36) not null,
       method    varchar(50) not null
   );
   
   -- 3. 授权类型表
   create table oauth2_client_grant_type
   (
       id         varchar(36) primary key,
       client_id  varchar(36) not null,
       grant_type varchar(50) not null
   );
   
   -- 4. 重定向uri表
   create table oauth2_client_redirect_uri
   (
       id           varchar(36) primary key,
       client_id    varchar(36)  not null,
       redirect_uri varchar(500) not null
   );
   
   -- 5. 客户端作用域表
   create table oauth2_client_scope
   (
       id           varchar(36) primary key,
       client_id    varchar(36)  not null,
       scope        varchar(100) not null
   );
   
   -- 6. 客户端设置表
   create table oauth2_client_settings
   (
       id                                              varchar(36) primary key,
       client_id                                       varchar(36),
       require_proof_key                               boolean default false,
       require_authorization_consent                   boolean default false,
       jwk_set_url                                     varchar(500),
       token_endpoint_authentication_signing_algorithm varchar(50)
   );
   
   -- 7. Token设置表
   create table oauth2_client_token_settings
   (
       id                                              varchar(36) primary key,
       client_id                                       varchar(36),
       access_token_time_to_live                       bigint,
       refresh_token_time_to_live                      bigint,
       reuse_refresh_token                             boolean default false,
       access_token_format                             varchar(50),
       id_token_signature_algorithm                    varchar(50)
   );
   ```
   </details><br>

- **自定义`RegisteredClientRepository`**
  <br>
   <details>
     <summary>Oauth2RegisteredClientService.java</summary>

   ```
   /**
    * Oauth2RegisteredClientService 已实现 RegisteredClientRepository 接口，无需重复定义 Bean。
    */
   @Repository
   @Transactional(readOnly = true)
   @RequiredArgsConstructor
   public class Oauth2RegisteredClientService implements RegisteredClientRepository {
       /**
        * 将 RegisteredClient 存入 DB
        */
       @Override
       @Transactional
       public void save(RegisteredClient client) {
           clientDAO.findById(client.getId())
                   .ifPresentOrElse(
                           existing -> updateExisting(existing, client),
                           () -> createNew(client)
                   );
       }
  
       /**
        * 根据 id 查询客户端信息
        */
       @Override
       public RegisteredClient findById(String id) {
           return clientDAO.findById(id)
                   .map(this::toRegisteredClient)
                   .orElse(null);
       }
   
       /**
        * 根据 clientId 查询客户端信息（OAuth2 认证时使用）
        */
       @Override
       public RegisteredClient findByClientId(String clientId) {
           return clientDAO.findByClientId(clientId)
                   .map(this::toRegisteredClient)
                   .orElse(null);
       }
   }
   ```
   </details>
3. **自定义 JWKSource**
- **创建表存储客户端公私钥**
  <br>
   <details>
     <summary>密钥对表、服务类</summary>  

   ```sql
   -- 8. 密钥对表
   create table oauth2_client_keypair
   (
   id                                              varchar(36) primary key,
   client_id                                       varchar(36),
   public_key_pem                                  text,            -- PEM格式公钥（base64加密）
   private_key_pem                                 text,            -- PEM格式私钥（base64加密）
   key_id                                          varchar(36),     -- JWK中的kid
   expires_at                                      date             -- 密钥过期时间
   );
   ```
   ```java
   @Service
   @RequiredArgsConstructor
   public class Oauth2ClientKeypairService {
       private final Oauth2ClientKeypairDAO keypairDAO;
       /**
        * 为每一个 Client 生成密钥对
        * (仅针对 GrantType 为 PRIVATE_KEY_JWT 的 Client 进行设置)
        */
       public void generateKeypair(String clientId) {
           // 查找 clientId 下的有效密钥
           Optional<Oauth2ClientKeypair> existValid = keypairDAO.findValidByClientId(clientId, Instant.now());
           if(existValid.isEmpty()) {
               KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(4096);
               String[] keyPerms = KeyGeneratorUtil.toKeyPerm(keyPair);
               String kid = clientId + "-" + Instant.now().getEpochSecond();
               Oauth2ClientKeypair entity = new Oauth2ClientKeypair();
               entity.setClientId(clientId);
               entity.setPublicKeyPem(keyPerms[0]);
               entity.setPrivateKeyPem(keyPerms[1]);
               entity.setKeyId(kid);
               entity.setExpiresAt(Instant.now().plus(90, ChronoUnit.DAYS));  // 有效期默认3个月
               keypairDAO.save(entity);
           }
       }
   }
   ```
   </details><br>
- **配置`JWKSource`**
  <br>
   <details>
     <summary>JwkConfig.java</summary>
  
  ```java
    @Bean
    public JWKSource<SecurityContext> jwkSource(Oauth2ClientKeypairDAO keypairDAO) {
        return (jwkSelector, securityContext) -> {
            try {
                Console.log("==================> 从数据库加载所有有效的密钥对");
                List<Oauth2ClientKeypair> keypairs = keypairDAO.findValidKeys(Instant.now());
                List<JWK> jwks = CollUtil.newArrayList();
                if (CollUtil.isNotEmpty(keypairs)) {
                    jwks = keypairs.stream().map(k -> {
                        try {
                            RSAPublicKey publicKey = KeyGeneratorUtil.parsePublicKey(k.getPublicKeyPem());
                            RSAPrivateKey privateKey = KeyGeneratorUtil.parsePrivateKey(k.getPrivateKeyPem());
                            RSAKey jwk = new RSAKey.Builder(publicKey)
                                    .privateKey(privateKey)
                                    .keyID(k.getKeyId())
                                    .algorithm(JWSAlgorithm.RS256)
                                    .build();
                            Console.log("JWK 构建结果: {}", jwk.toJSONString());
                            return jwk;
                        } catch (Exception e) {
                            Console.log("密钥对解析失败: " + e.getMessage());
                            throw new IllegalStateException("Keypair 解析失败.", e);
                        }
                    }).collect(Collectors.toList());
                }
                return jwkSelector.select(new JWKSet(jwks));
            } catch (Exception e) {
                Console.log("发生异常: " + e.getMessage());
                throw new IllegalStateException("JWKSource 配置失败.", e);
            }
        };
    }
  
    /**
     * JWT 编码器
     * 将 JWT 的内容（Claims）和头部（Header）信息组合起来，并使用指定的加密算法进行签名，最终生成可用的 JWT 字符串
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        // 基于 Nimbus JOSE + JWT 库，自动从 JWKSource 选择合适的密钥进行签名
        NimbusJwtEncoder delegate = new NimbusJwtEncoder(jwkSource);
        return parameters -> {
            Console.log("==================> JwtEncoder.encode 被调用！");
            return delegate.encode(parameters);
        };
    }
  
    /**
     * JWT 解码器
     * 1. 授权服务器: 仅在授权服务器内部使用 JWT（如生成访问令牌）, 不需要 JWT 解码器
     * 2. 资源服务器: 需要验证 JWT 令牌（例如访问受保护 API），必须显式配置 JwtDecoder
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
  
    @Bean
    public OAuth2TokenGenerator<?> jwtTokenGenerator(JwtEncoder jwtEncoder) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        // 生成器会按注册顺序执行, 第一个能处理当前令牌类型的生成器将被使用
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                accessTokenGenerator,
                refreshTokenGenerator
        );
    }
  ```
   </details>

4. **配置授权服务器**
   <br>
   <details>
     <summary>AuthorizationServerConfig.java</summary>
   
   ```java
   @Configuration
   public class AuthorizationServerConfig {
      @Bean
      @Order(1)
      public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
          OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
          // 获取所有OAuth2授权服务器端点的匹配器
          RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
          http
             .securityMatcher(endpointsMatcher)
             .with(authorizationServerConfigurer, asConfig -> {})
             .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
             .exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
             .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher)); // 对所有授权服务器端点禁用 CSRF
          return http.build();
      }
   
      /**
       * 授权服务器Endpoint设置 (必配置项)
       * 定义 OAuth 2.0 授权服务器的各种端点 URL 和服务器相关设置
       */
      @Bean
      public AuthorizationServerSettings authorizationServerSettings() {
          AuthorizationServerSettings serverSettings = AuthorizationServerSettings.builder().build();
          return AuthorizationServerSettings.builder()
                    .issuer("http://localhost:8001")
                    .authorizationEndpoint("/oauth2/authorize")
                    .tokenEndpoint("/oauth2/token")
                    .jwkSetEndpoint("/oauth2/jwks.json")    // 同 clientSettings 下的 jwkSetUrl
                    .build();
      }
   }
   ```
   </details><br>

5. **添加其他安全配置**
   <br>
   <details>
     <summary>SecurityConfig.java</summary>

   ```java
   @Configuration
   public class SecurityConfig {
       /**
        * 用于普通 Web 应用的安全控制（主要配置用户认证）
        */
       @Bean
       @Order(2)    // 优先级低于授权服务器
       public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http
                .headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/favicon.ico", "/css/**", "/js/**", "/h2-console/**").permitAll()
                    .requestMatchers("/oauth2/jwt/*", "/oauth2_client/register").permitAll()
                    .anyRequest().authenticated()
                )
                .formLogin(form -> form
                    .loginPage("/login")    // 指定登录页
                    .defaultSuccessUrl("/")
                    .failureUrl("/login?error=true")
                    .permitAll()
                )
                .logout(logout -> logout
                    .logoutSuccessUrl("/login?logout=true")
                    .permitAll()
                )
                .csrf(csrf -> csrf
                    .ignoringRequestMatchers("/h2-console/**")
                );
            return http.build();
       }
   
       /**
        * 身份验证实现
        */
       @Bean
       public AuthenticationManager authenticationManager(UserDetailsService userService, PasswordEncoder passwordEncoder) {
           DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
           daoAuthenticationProvider.setUserDetailsService(userService);
           daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
           return new ProviderManager(daoAuthenticationProvider);
       }
   }
   ```
   </details><br>

    

6. **注意要点**
    - 密钥必须带有标记
    ```markdown
    -----BEGIN PUBLIC KEY-----
    <你的PublicKey>
    -----END PUBLIC KEY-----
    -----BEGIN PRIVATE KEY-----
    <你的PrivateKey>
    -----END PRIVATE KEY-----
    ```
    - Jwt 要显示指定 type、Alg、keyId
    - 客户端要显示指定 `tokenEndpointAuthenticationSigningAlgorithm`
    - AccessToken 在 https://jwt.io 中进行验证

7. **测试方式**
   
   <details>
     <summary>授权码模式</summary>
   
    ```shell
    ## 1. 先登录, 浏览器访问:     http://localhost:8001/login
    ## 2. 获取授权码, 浏览器访问:  http://localhost:8001/oauth2/authorize?client_id=<你的ClientId>&response_type=code&scope=read
    
        访问：http://localhost:8001/oauth2/authorize?client_id=secret-basic-client&response_type=code&scope=user.read
        得到：http://localhost:8001/login/oauth2/code/secret-basic-client?code=11WhvDY0ORz0h8J7aZGyFE9Dd_josK8Il9kbuJ2UevBke487W9U7DjKgoSBVmQaUpA6OcTIko3XB74R3Y8W8n-78yhsJ5hWh2cdpRXMbKmMBB5JnnoAwcd3LKRpULeZX
        
    ## 3. 获取Token（Basic Auth 认证）
    curl -X POST "http://localhost:8001/oauth2/token" \
        -u "<你的client_id>:<你的client_secret>" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=authorization_code&code=<你的授权码>&redirect_uri=http://localhost:8001/login/oauth2/code/<你的client_id>"
    
    curl -X POST "http://localhost:8001/oauth2/token" \
          -u "secret-basic-client:secret-basic-secret" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -d "grant_type=authorization_code&code=<code>&redirect_uri=http://localhost:8001/login/oauth2/code/secret-basic-client"
          
    # 或 -H "Authorization: Basic $(echo -n '<你的client_id>:<你的client_secret>' | base64)" === -u "<你的client_id>:<你的client_secret>"
    curl -X POST http://localhost:8001/oauth2/token \
    -H "Authorization:Basic c2VjcmV0LWJhc2ljLWNsaWVudDpzZWNyZXQtYmFzaWMtc2VjcmV0" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token" \
    -d "grant_type=authorization_code&code=<你的授权码>&redirect_uri=http://localhost:8001/login/oauth2/code/<你的client_id>"
    ```
    </details><br>

    <details>
     <summary>密码模式 ( private_key_jwt )</summary>
   
    ```shell
    ## 1. 生成jwt。 curl http://localhost:8001/oauth2/jwt/<client_id>
    curl http://localhost:8001/oauth2/jwt/private-key-client 
    
    ## 客户端公钥存储地址 http://localhost:8001/oauth2/jwks
    
    ## 2. 请求获取 Token
    curl -X POST \
       -H "Content-Type:application/x-www-form-urlencoded" \
       -d "grant_type=client_credentials" \
       -d "client_id=private-key-client" \
       -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
       -d "scope=api.read" \
       -d "client_assertion=<你的JWT>" \
     'http://localhost:8001/oauth2/token'
        
    curl -X POST \
       -H "Content-Type:application/x-www-form-urlencoded" \
       -d "grant_type=client_credentials" \
       -d "client_id=private-key-client" \
       -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
       -d "scope=api.read" \
       -d "client_assertion=eyJraWQiOiJwcml2YXRlLWtleS1jbGllbnQtMTc0NjkzNzc1NyIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJwcml2YXRlLWtleS1jbGllbnQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwMDEvb2F1dGgyL3Rva2VuIiwiaXNzIjoicHJpdmF0ZS1rZXktY2xpZW50IiwiZXhwIjoxNzQ2OTM4MzgwLCJpYXQiOjE3NDY5Mzc3ODAsImp0aSI6IjI3NzRkMGIwLTk3NTQtNDc3Ni05MDE1LTM5MTIzM2MyZjVmMiJ9.IimOc5bYnnNOuZZXbnz9jSNdn5TvmXCAxi01PbW6dEqtsxYsEcym73qUVHZrkdi5Q6KuvOFrPCUEtvyRd8vXQMCE1IOqpmwqUiiJSNW_ukM3p4TyEaUxodWVBUzSRBRQP-1nWx4LTlN8Qe2e-28YoH7a-7oeJPhIGfUC4dEiWsaG8wnXPwd0DcncJb9RRi7FbvGR2itRi973vybId4UJY-Pi8CW770pT-AF5tJwXVp8CSQLJ_naF09VRF3andBe0yO0HJ7K5VcmGNR0ms3kKFAk_rJVw5h-ieugmSE6SLXTKaxlQYwkUDFAWVlE0uoZAlyZLgGT33XyJ_O7s2PVBwLc86eTX3oZNgjukaLGrr6jv5MUA7iTe3bUE1UhB_O4ejFT_EcZBYupPZ8XB4u6btZlhxYEn59Wuo4up5ueTUid3gCM7upSeCs5N1vgLZzNynrXCgq7JlHgRes5fUs0anmGyRlJG1L8weZeofwKXdwpdU0d134wcdb4PeGHVIHqbCYhxOOFB9BrdB23Ea0MKT2XNdaphY5IFfQziuijardTn76ix3t30DBsnKEYOJiKfkK8GYPhkZThGW3tSlW7dzju_GKw1KemkQc-zi3DmoDdZu7PHuqm77LBoAby7Am71fATpNnZE6-6XEQxUQUv08yFQgKiN2zID1lMmorVWHIU" \
     'http://localhost:8001/oauth2/token'
    ```

</details>

8. **客户端自动续期**

- 对于授权码模式，正确流程: 
  
    (1) 用户访问客户端发起授权请求
    
    (2) 浏览器跳转到授权服务器，登录并授权
    
    (3) 授权服务器将 code 回调到客户端（携带 redirect_uri）
    
    (4) 客户端用这个 code 换 token（只允许一次）
    
    (5) 获得 access_token 和 refresh_token
    
- 如需再次获取 token，请使用 refresh_token
  
    (1) 开启 refresh token 支持`authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)`
    
    (2) 在 token 过期前用 refresh_token 请求新的 token
    ```shell
    curl -X POST http://localhost:8001/oauth2/token \
      -u "secret-basic-client:secret-basic-secret" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=refresh_token" \
      -d "refresh_token=xxxxxx"
    ```
- Spring 的处理方式

    (1) Spring Authorization Server 会生成一个 OAuth2AccessToken；
    
    (2) 如果你的 token 是 JWT（默认是），它会调用 JwtEncoder；
    
    (3) JwtEncoder 会通过你配置的 JWKSource<SecurityContext> 获取密钥对来签名 JWT；
    
    因此，每次发 token 时都会调用你注册的 jwkSource bean。jwkSource bean 中需要缓存优化处理。

### 三. OIDC（OpenID Connect）

（1）启用 OIDC  (AuthorizationServerConfig)

（2）配置 Issuer URI  (AuthorizationServerSettings)

```java
AuthorizationServerSettings.builder().issuer("http://localhost:8001")    // 发布后需要设置公网地址
```

（3）自定义 ID Token 的声明 (OAuth2TokenCustomizer)

（4）实现 UserInfo Endpoint (UserInfoMapper)

```java
.oidc(oidc -> oidc
          .userInfoEndpoint((userInfo) -> userInfo
              .userInfoMapper(userInfoMapper())
))
```

（5）确保 JWKS URI 可用并包含签名密钥 (JWKSource bean)

（7）确保客户端注册时包含 openid scope (RegisteredClient)

```java
scope(OidcScopes.OPENID)
```

### 四. 单点登出 SLO

对于用户注销，有三种场景需要考虑

- 本地注销
- 应用 RP 发起注销，同时注销应用程序和 `OIDC Provider`
- `OIDC Provider`，发起注销，同时注销应用程序和 `OIDC Provider`

#### 1. RP-Initiated Logout

RP-Initiated Logout 是 OpenID Connect (OIDC) 定义的一种客户端（Relying Party，简称 RP）主动发起注销的机制，适用于用户点击“退出登录”时，希望用户在 RP 和授权服务器（Identity Provider, IdP）两侧都完成会话清理的场景。

**作用**

- **由客户端（RP）主动发起**：用户通过客户端的界面（如“退出登录”按钮）触发注销流程。
- **基于前端通信**：通过浏览器重定向（前端通道）通知身份提供商（IdP）和其他相关客户端注销会话。
- **依赖用户代理（浏览器）**：通过前端跳转传递注销请求和状态。

**适用场景**

- **多系统登录联动**
  - 用户通过 IdP 登录多个系统（即多个 RP）
  - 当用户在某个 RP 中点击退出，期望注销所有系统会话
  - 如涉及支付、个人隐私、企业后台等，需要确保用户退出后，所有会话都被清除
- **单点登录（SSO）体系中的一环，SSO 中，登录和退出都应被统一管理**

**优点**

- **统一会话管理**：客户端发起注销请求可显式通知 IdP 清除会话
- **用户体验良好**：从 RP 发起跳转，不依赖用户手动去 IdP 页面
- **符合现代架构设计**： 适合前后端分离、微服务架构
- **标准化**：符合 OIDC 标准，可与多种 IdP 兼容

**缺点**

- **无法通知其他 RP**：仅注销当前 RP 和 IdP 之间的会话，不能自动通知其他 RP
- **依赖前端跳转**：是前端重定向实现，不适用于无 UI 场景
- **需要客户端显式配置**：要求注册 `post_logout_redirect_uri`，安全策略较严格

**功能实现**

- **IdP 端**

```java
// 1. 开启 OIDC 支持（包括 AS 配置和注册客户端的 scope = openid）
// 2. 注册客户端中，设置 postLogoutRedirectUri("<和客户端中保持一致>")
```

- **RP 端**

```java
// 1. 设置 issuer-uri
// 2. 配置 OidcClientInitiatedLogoutSuccessHandler
.logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler())
        
private LogoutSuccessHandler oidcLogoutSuccessHandler() {
		OidcClientInitiatedLogoutSuccessHandler oidcHandler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        oidcHandler.setPostLogoutRedirectUri("{baseUrl}/logout-success");
  	return (request, response, authentication) -> {
            if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
                String registrationId = oauth2Token.getAuthorizedClientRegistrationId();

                // 不支持 OIDC, 进行本地注销操作
                if ("github".equals(registrationId) || "gitee".equals(registrationId)) {
                    // GitHub 不支持 OIDC logout，仅清理 session
                    request.logout();
                    response.sendRedirect("/client"); // 或跳转到登录页
                    return;
                }

                // OIDC 处理（本地 AS）
                oidcHandler.onLogoutSuccess(request, response, authentication);
            } else {
                // 非 OAuth2 登录，默认登出处理
                response.sendRedirect("/");
            }
        };
}
        
// 3. 开放 /logout-success
.requestMatchers("/logout-success").permitAll()
```

#### 2. Back-Channel Logout

当前版本1.4.3，此功能还不可用，等待未来版本支持。


### 三. 大型系统设计

```pgsql
               +-------------------------+
               |     客户端 (SPA/APP)    |
               +-------------------------+
                          |
                          v
               +-------------------------+
               |     统一认证入口 (SSO)   |
               +-------------------------+
                          |
         +----------------+----------------+
         |                                 |
         v                                 v
+------------------+            +----------------------+
| 授权服务器 (AuthZ) |<---------> | 用户中心 (UserCenter) |
+------------------+            +----------------------+
|
| 发放 Token (JWT / Opaque)
v
+-------------------------+
|     资源服务器 A        |
| (用户服务 / 订单服务等) |
+-------------------------+
|
v
+-------------------------+
|     权限网关 (可选)     |
+-------------------------+
```

1. 授权服务器（Authorization Server）
   - Resource Server 注册后台
     - scope 列表配置
     - client - scope 映射关系
   - Client 注册后台
     - CRUD client
     - 配置授权方式、client_secret、redirect_uri 等
   - 提供 /authorize, /token, /revoke, /userinfo 等端点；
   - 认证用户（支持密码、短信、微信扫码等）；
   - 授权客户端（client_id/secret、PKCE 等）；
   - 生成并签发 Access Token、Refresh Token；


2. 资源服务器（Resource Server）

   - 验证 Access Token；
   - 提取 scope/roles 判定资源访问控制；
   - 可以多个，分别承载业务系统；
   - 安全控制：
        - @PreAuthorize("hasAuthority('SCOPE_read_user')")
        - 配置 JWT 解码器与权限解析器

3. 用户中心（User Center）
   - 提供统一用户数据存储与验证：
     - 登录信息（账号、密码、OTP）
     - 用户资料（邮箱、手机号）
     - 第三方绑定（微信、GitHub、钉钉等）
   - 可支持多认证方式：
     - 密码、验证码、社交登录、LDAP、CAS、SAML 等

4. 客户端（Client）
   - Web App（浏览器端）
   - Mobile App（iOS/Android）
   - CLI 工具
   - 第三方集成服务（如 Webhook）

5. 网关/权限网关（可选）
   - Token 校验
   - 动态路由
   - 多租户、限流、灰度发布