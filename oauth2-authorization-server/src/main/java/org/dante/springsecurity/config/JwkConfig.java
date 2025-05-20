package org.dante.springsecurity.config;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.lang.Console;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.dante.springsecurity.dao.Oauth2ClientKeypairDAO;
import org.dante.springsecurity.entity.Oauth2ClientKeypair;
import org.dante.springsecurity.security.KeyGeneratorUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWK (JSON Web Key) 生成和管理
 */
@Configuration
public class JwkConfig {

// TODO: 待优化：缓存 JWK 响应
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

}
