# Spring OAuth2 授权、资源服务器

| 功能  | 资源服务器            | 授权服务器                                     |
|---|------------------|-------------------------------------------|
| 核心职责 | 保护资源，验证访问令牌的合法性  | 颁发访问令牌，管理客户端和用户的认证与授权                     |
| 依赖关系  | 依赖授权服务器提供令牌验证支持（如公钥）  | 独立运行，提供令牌签发和验证端点（如 /oauth2/token）         |
| 典型实现  | `Spring Security + oauth2-resource-server`  | `Spring Authorization Server`、`Keycloak`、`Okta` |

## 一. 授权服务器
**Spring OAuth2 Authorization Server**


## 二. 资源服务器
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
curl -X POST "http://localhost:8001/oauth2/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=<client_id>&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=<你的JWT>&scope=api.read"
      
curl -X POST http://localhost:8001/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials& \
      client_id=private-key-client&\
      client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer& \
      client_assertion=eyJraWQiOiJwcml2YXRlLWtleS1jbGllbnQtMTc0Njg4MzAyOSIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJwcml2YXRlLWtleS1jbGllbnQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwMDEvb2F1dGgyL3Rva2VuIiwiaXNzIjoicHJpdmF0ZS1rZXktY2xpZW50IiwiZXhwIjoxNzQ2ODgzNzcxLCJpYXQiOjE3NDY4ODMxNzEsImp0aSI6IjNiNGI1NTMwLWE0NGYtNDNhZi1iZGU0LWQwM2ZhM2U5NTIwOCJ9.aseHVvDlGn5khEj4uC5-7lXpbUEmnCqm724J9TXa5QcPZEZycEpzJaSuqTxr7BjuBCDrFgU1D8trm9Y_MBvCeWPmeZ_IaSd32WNuqSLhK57CC_AQUXp2UsxoFanQ2OxxCFL5st82Nb56sTF1Bu6pZr9hr4BOWFnePK4Hv3aDeHkZYpQC39qHxfTEYDkplPTxqIDsvmRIjS_9lPa02Y-XLEvvSeEBreFNHF42T__OeTLZjlWVkY7OXymqGVtrVFvDB1jI1SfTulQ4LqTX42F35Ycp8HfpxI7JRLrmt88zJ9p9NgN3tGeeSE9zp77Baa6CEv9-jPWxHhhqiU_3xs-yIy1Yzxfrr7-s9FEWsdj1J282YDDGBag1jldq_g7XnFhEoWJEQoyRKrN7FUkYNMaz1hCTgz3raMqwMLyLirs0Mg1WrXMt6lugD0OGDoVn8GV8Hsy_ePPSm-cLl_OdfCNXZ_fI94FGuyX71xTvUcqdfgKrtHTlTDHLQ7IHrkeZTSE4JOj_oAmVzJ7KLBys1p47ZD-EPy4l0URLzkvhzX3NckyDUHAPL3A-UbtHF6JHtuOFJCD9I06Oy9jdCpZUJwo3OB6YAEXZcQZyLu-YQaXqihb2f5faNcR5srEbAzjwqk94ynDadbiRr15AQz5F2iAnhfekrBBmqlOXzycC_0-O62c&\
      scope=api.read"
```