package org.dante.springsecurity.security;

import cn.hutool.crypto.asymmetric.RSA;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.IOUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class KeyGeneratorUtil {

    /**
     * 生成RSA密钥对
     */
    public static KeyPair generateRsaKeyPair() {
        return generateRsaKeyPair(2048);
    }

    @SneakyThrows
    public static KeyPair generateRsaKeyPair(int keySize) {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 为OAuth2 PRIVATE_KEY_JWT 生成 RSA JWK
     */
    public static RSAKey generateRsaJwk() {
        return generateRsaJwk(2048, UUID.randomUUID().toString());
    }

    public static RSAKey generateRsaJwk(String keyId) {
        return generateRsaJwk(2048, keyId);
    }

    public static RSAKey generateRsaJwk(int keySize, String keyId) {
        KeyPair keyPair = generateRsaKeyPair(keySize); // 生成 RSA KeyPair
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(keyId)
                .build();
    }

    public static RSAKey generateRsaJwk(RSAPublicKey publicKey, RSAPrivateKey privateKey, String keyId) {
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();
    }

    /**
     * 将密钥对转换为PEM格式（包含标准的头尾标记）
     *
     * @return String[]{ publicKeyPerm, privateKeyPerm }
     */
    public static String[] toKeyPerm(KeyPair keyPair) {
        // 将密钥对转换为JWK格式
        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .build();
        RSA rsa = new RSA(keyPair.getPrivate(), keyPair.getPublic());
        return new String[]{toPublicKeyPerm(rsa.getPublicKeyBase64()), toPrivateKeyPerm(rsa.getPrivateKeyBase64())};
    }

    /**
     * 将公钥转换为PEM格式（包含标准的头尾标记）
     */
    public static String toPublicKeyPerm(String publicKeyBase64) {
        return "-----BEGIN PUBLIC KEY-----\n" + publicKeyBase64 + "\n-----END PUBLIC KEY-----\n";
    }

    /**
     * 将私钥钥转换为PEM格式（包含标准的头尾标记）
     */
    public static String toPrivateKeyPerm(String privateKeyBase64) {
        return "-----BEGIN PRIVATE KEY-----\n" + privateKeyBase64 + "\n-----END PRIVATE KEY-----\n";
    }

    /**
     * 从PEM格式（包含标准的头尾标记）解析公钥
     */
    public static RSAPublicKey parsePublicKey(String publicKeyPerm) {
        String publicKeyBase64 = publicKeyPerm
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        RSA rsa = new RSA(null, publicKeyBase64);
        return (RSAPublicKey) rsa.getPublicKey();
    }

    /**
     * 从PEM格式（包含标准的头尾标记）解析私钥
     */
    public static RSAPrivateKey parsePrivateKey(String privateKeyPerm) {
        String privateKeyBase64 = privateKeyPerm
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        RSA rsa = new RSA(privateKeyBase64, null);
        return (RSAPrivateKey) rsa.getPrivateKey();
    }

    /**
     * 将密钥保存到文件
     */
    @SneakyThrows
    public static void saveKeysToFile(String publicKeyPem, String privateKeyPem,
                                      String publicKeyPath, String privateKeyPath) {
        try (FileWriter publicWriter = new FileWriter(publicKeyPath)) {
            publicWriter.write(publicKeyPem);
        }

        try (FileWriter privateWriter = new FileWriter(privateKeyPath)) {
            privateWriter.write(privateKeyPem);
        }
    }

    /**
     * 从文件读取PEM格式的密钥
     */
    public static String readPemFromFile(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            return IOUtils.readInputStreamToString(fis);
        }
    }

    /**
     * 每 64 字符换行
     */
    public static String formatBase64(String keyBase64) {
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < keyBase64.length(); i += 64) {
            formatted.append(keyBase64, i, Math.min(i + 64, keyBase64.length())).append("\n");
        }
        return formatted.toString().trim();
    }

}
