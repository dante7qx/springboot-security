package org.dante.springsecurity.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.Serializable;
import java.util.UUID;

/**
 * 客户端认证方式表
 *
 */
@Entity
@Table(name = "oauth2_client_post_logout_redirect_uri")
@Data
@ToString(exclude = "client")
@EqualsAndHashCode(exclude = "client")
public class Oauth2ClientPostLogoutRedirectUri implements Serializable {

    @Id
    private String id;
    @ManyToOne
    @JoinColumn(name = "client_id")
    private Oauth2Client client;
    private String logoutRedirectUri;

    public Oauth2ClientPostLogoutRedirectUri() {
        this.id = UUID.randomUUID().toString();
    }

    public static Oauth2ClientPostLogoutRedirectUri from(Oauth2Client client, String logoutRedirectUri) {
        Oauth2ClientPostLogoutRedirectUri entity = new Oauth2ClientPostLogoutRedirectUri();
        entity.setClient(client);
        entity.setLogoutRedirectUri(logoutRedirectUri);
        return entity;
    }

}
