package org.dante.springsecurity.service;

import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.dao.Oauth2ClientKeypairDAO;
import org.dante.springsecurity.entity.Oauth2ClientKeypair;
import org.dante.springsecurity.security.KeyGeneratorUtil;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;


/**
 * 密钥对生成服务类
 */
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

