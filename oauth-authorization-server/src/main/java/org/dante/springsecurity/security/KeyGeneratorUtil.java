package org.dante.springsecurity.security;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class KeyGeneratorUtil {

    public static RSAKey generateRsaKey() {
        KeyPair keyPair = generateRsaKeyPair(); // 生成 RSA KeyPair
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    /**
     * 生成RSA密钥对
     *
     * @return KeyPair
     */
    public static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

}
