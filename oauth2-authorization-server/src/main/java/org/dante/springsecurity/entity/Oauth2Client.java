package org.dante.springsecurity.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.Serializable;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * 主客户端表
 *
 */
@Entity
@Table(name = "oauth2_client")
@Data
@ToString(exclude = {"authMethods", "grantTypes", "redirectUris", "logoutRedirectUris", "scopes", "tokenSettings", "clientSettings"})
@EqualsAndHashCode(exclude = {"authMethods", "grantTypes", "redirectUris", "logoutRedirectUris", "scopes", "tokenSettings", "clientSettings"})
public class Oauth2Client implements Serializable {

    @Id
    private String id;

    @Column(name = "client_id", unique = true)
    private String clientId;

    private String clientSecret;

    /** ClientId 发布时间 */
    private Instant issuedAt;

    /** ClientSecret 过期时间 */
    private Instant expiresAt;

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<Oauth2ClientAuthMethod> authMethods = new HashSet<>();

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<Oauth2ClientGrantType> grantTypes = new HashSet<>();

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<Oauth2ClientRedirectUri> redirectUris = new HashSet<>();

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<Oauth2ClientPostLogoutRedirectUri> logoutRedirectUris = new HashSet<>();

    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<Oauth2ClientScope> scopes = new HashSet<>();

    @OneToOne(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Oauth2ClientTokenSettings tokenSettings;

    @OneToOne(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Oauth2ClientSettings clientSettings;

    public Oauth2Client() {
        this.id = UUID.randomUUID().toString();
    }

    public Oauth2Client(String id) {
        this.id = id;
    }

}
