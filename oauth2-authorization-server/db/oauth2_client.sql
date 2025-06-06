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

-- 8. 密钥对表
create table oauth2_client_keypair
(
    id                                              varchar(36) primary key,
    client_id                                       varchar(36),
    public_key_pem                                  text,            -- PEM格式公钥（base64加密且带有标记）
    private_key_pem                                 text,            -- PEM格式私钥（base64加密且带有标记）
    key_id                                          varchar(36),     -- JWK中的kid
    expires_at                                      date             -- 密钥过期时间
);

-- 9. oidc logout 回调 uri
create table oauth2_client_post_logout_redirect_uri
(
    id           varchar(36) primary key,
    client_id    varchar(36)  not null,
    logout_redirect_uri varchar(500) not null
);

-- TODO: 以下表待具体实现

-- 10. 资源服务器
create table oauth2_resource_server
(
    id                                              varchar(36) primary key,
    resource_server_id                              varchar(36),
    resource_server_name                            varchar(64),
    remark                                          varchar(1024)
);

-- 11. 资源服务器 scope
create table oauth2_resource_server_scope
(
    id                                              varchar(36) primary key,
    resource_server_id                              varchar(36),
    scope                                           varchar(64),
    scope_desc                                      varchar(128)
);

-- 12. 资源服务器 client - scope 映射
create table oauth2_resource_server_client_scope
(
    id                                              varchar(36) primary key,
    client_id                                       varchar(36),
    scope                                           varchar(64),
    remark                                          varchar(1024)
);