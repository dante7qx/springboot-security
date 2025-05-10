package org.dante.springsecurity.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

/**
 * 客户端密钥对
 */
@Entity
@Table(name = "oauth2_client_keypair")
@Data
public class Oauth2ClientKeypair implements Serializable {

    @Id
    private String id;

    @Column(unique = true)
    private String clientId;

    @Lob
    private String publicKeyPem;  // PEM格式公钥

    @Lob
    @JsonIgnore
    private String privateKeyPem; // PEM格式私钥

    private String keyId;         // JWK中的kid

    private Instant expiresAt;    // 密钥过期时间

    public Oauth2ClientKeypair() {
        this.id = UUID.randomUUID().toString();
    }

}