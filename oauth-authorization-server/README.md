## Spring OAuth2 授权、资源服务器

| 功能          | 资源服务器                                        | 授权服务器                                     |
|-------------|----------------------------------------------|-------------------------------------------|
| 核心职责        | 保护资源，验证访问令牌的合法性                              | 颁发访问令牌，管理客户端和用户的认证与授权                     |
| 依赖关系        | 依赖授权服务器提供令牌验证支持（如公钥）                         | 独立运行，提供令牌签发和验证端点（如 /oauth2/token）         |
| 典型实现        | `Spring Security + oauth2-resource-server`   | `Spring Authorization Server`、`Keycloak`、`Okta` |

### 一. 授权服务器

#### 1. 概述
OAuth2是一种授权框架，允许第三方应用获取对用户账户的有限访问权限，而无需获取用户的凭证。授权服务器是OAuth2体系中的核心组件，负责验证用户身份并颁发访问令牌。

**OAuth2授权服务器核心功能**
1. 用户认证：验证资源所有者(用户)的身份
2. 颁发授权码和访问令牌：根据不同的授权流程生成相应的令牌
3. 管理客户端应用注册：维护可信任的第三方应用列表
4. 支持多种授权模式：授权码模式、隐式授权、客户端凭证、资源所有者密码凭证等
5. 令牌管理：包括令牌的创建、校验、刷新和撤销

**Spring OAuth2 Authorization Server**

**Spring Authorization Server**是Spring生态系统中专门用于构建`OAuth2.0`和`OpenID Connect 1.0`授权服务器的框架。

1. `OAuth2`核心规范支持
   - 完整支持`OAuth2.0`框架(RFC6749)
   - 支持所有标准授权类型：授权码、客户端凭证、资源所有者密码凭证等
   - 支持令牌撤销(RFC7009)和令牌内省(RFC7662)

2. `OpenID Connect`支持
   - 支持`OpenID Connect Core 1.0`
   - 支持ID令牌、用户信息端点
   - 支持标准声明集

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

#### 2. 功能实现

[代码地址](https://github.com/dante7qx/springboot-security/tree/2.7.x)

1. **创建`Springboot`项目**
```xml
<parent>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-parent</artifactId>
     <version>2.7.18</version>
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
   <version>0.4.5</version>
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
      @Order(1) // 高优先级
      public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
          OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
          // 获取所有OAuth2授权服务器端点的匹配器
          RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
          http
              .requestMatcher(endpointsMatcher)
              .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
              .exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
              // 对所有授权服务器端点禁用 CSRF
              .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
              .apply(authorizationServerConfigurer);
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
               .csrf().disable()
               .authorizeRequests(request ->
                       request.requestMatchers(
                               new AntPathRequestMatcher("/favicon.ico"),
                               new AntPathRequestMatcher("/h2-console/**"),
                               new AntPathRequestMatcher("/oauth2/jwt/*")
                       ).permitAll()
                       .anyRequest().authenticated()
               )
               .formLogin(Customizer.withDefaults());
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
   </details>

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


### 二. 资源服务器
**Spring OAuth2 Resource Server**


### 测试方式

1. **授权码**
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
      
```
2. **密码模式 ( private_key_jwt )**
```shell
## 1. 生成jwt。 curl http://localhost:8001/oauth2/jwt/<client_id>
curl http://localhost:8001/oauth2/jwt/private-key-client 

## 客户端公钥存储地址 http://localhost:8001/oauth2/jwks.json

## 2. 请求获取 Token
curl -i -X POST \
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