package org.dante.springsecurity.controller;

import cn.hutool.core.lang.Console;
import cn.hutool.core.util.IdUtil;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.dante.springsecurity.dao.Oauth2ClientKeypairDAO;
import org.dante.springsecurity.entity.Oauth2ClientKeypair;
import org.dante.springsecurity.security.KeyGeneratorUtil;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 自定义 jwkSet Endpoint（一般不需要自定义）
 * 需要显示的替换 AuthorizationServerSettings 的 jwkSetEndpoint。并配置允许匿名访问
 */
@RestController
@RequestMapping("/oauth2")
@RequiredArgsConstructor
public class Oauth2JwkController {

    private final Oauth2ClientKeypairDAO keypairDAO;
    private final AuthorizationServerSettings serverSettings;

    @GetMapping("/jwks.json")
    public Map<String, Object> getJwks() {
        List<JWK> jwks = keypairDAO.findValidKeys(Instant.now()).stream()
                .map(k -> {
                    try {
                        RSAPublicKey publicKey = KeyGeneratorUtil.parsePublicKey(k.getPublicKeyPem());
                        return new RSAKey.Builder(publicKey)
                                .keyID(k.getKeyId())
                                .algorithm(JWSAlgorithm.RS256)
                                .build(); // 注意：只构建公钥 JWK，不设置 .privateKey()
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }).collect(Collectors.toList());

        JWKSet jwkSet = new JWKSet(jwks);
        return jwkSet.toJSONObject();
    }

    /**
     * 生成客户端私钥签名 JWT
     */
    @SneakyThrows
    @GetMapping("/jwt/{clientId}")
    public Map<String, String> generateJwt(@PathVariable("clientId") String clientId) {
        String jwt = "";
        Instant now = Instant.now();
        Optional<Oauth2ClientKeypair> keypair = keypairDAO.findValidByClientId(clientId, now);
        if (keypair.isPresent()) {
            Oauth2ClientKeypair clientKey = keypair.get();
            String audience = serverSettings.getIssuer() + serverSettings.getTokenEndpoint();
            String jwtID = IdUtil.randomUUID();
            RSAPrivateKey rsaPrivateKey = KeyGeneratorUtil.parsePrivateKey(clientKey.getPrivateKeyPem());
            // Nimbus JOSE + JWT 生成 JWT
            JWSSigner jwsSigner = new RSASSASigner(rsaPrivateKey);
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT) // 明确设置 typ
                    .keyID(clientKey.getKeyId()) // 设置 kid
                    .build();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience(audience)
                    .expirationTime(Date.from(now.plus(10, ChronoUnit.MINUTES)))
                    .issueTime(Date.from(now))
                    .jwtID(jwtID)
                    .build();
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            signedJWT.sign(jwsSigner);
            jwt = signedJWT.serialize();
        }
        Console.log("{} 生成 jwt-> {}", clientId, jwt);
        return Map.of("jwt", jwt);
    }

}
