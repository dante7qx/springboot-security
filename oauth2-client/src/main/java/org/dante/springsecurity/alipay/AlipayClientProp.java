package org.dante.springsecurity.alipay;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 支付宝登录
 * 沙箱环境：https://opendocs.alipay.com/open/09byox?pathHash=4e5b941b
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "alipay")
public class AlipayClientProp {

    private String alipayGateway;

    private String appId;
    private String format = "json";
    private String charset = "utf-8";
    private String signType = "RSA2";
    private String privateKey;              // 对请求参数进行签名
    private String publicKey;               // 上传支付宝, 用于支付宝平台校验你的签名
    private String alipayPublicKey;         // 用于验签支付宝的响应或异步通知
    private String version = "1.0";

}


/*
     商家信息

        商户账号 djpavt0726@sandbox.com
        登录密码 111111
        商户PID 2088721068351843

    买家信息

        买家账号 gbtmma9244@sandbox.com
        登录密码 111111
        支付密码 111111
        用户UID 2088722068321760
        用户名称 gbtmma9244
        证件类型 IDENTITY_CARD
        证件账号 174853194601217411
 */