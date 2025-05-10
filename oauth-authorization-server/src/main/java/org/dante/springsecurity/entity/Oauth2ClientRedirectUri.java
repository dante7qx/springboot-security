package org.dante.springsecurity.entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;
import java.util.UUID;

/**
 * 客户端认证方式表
 *
 */
@Entity
@Table(name = "oauth2_client_redirect_uri")
@Data
@ToString(exclude = "client")
@EqualsAndHashCode(exclude = "client")
public class Oauth2ClientRedirectUri implements Serializable {

    @Id
    private String id;
    @ManyToOne
    @JoinColumn(name = "client_id")
    private Oauth2Client client;
    private String redirectUri;

    public Oauth2ClientRedirectUri() {
        this.id = UUID.randomUUID().toString();
    }

    public static Oauth2ClientRedirectUri from(Oauth2Client client, String redirectUri) {
        Oauth2ClientRedirectUri entity = new Oauth2ClientRedirectUri();
        entity.setClient(client);
        entity.setRedirectUri(redirectUri);
        return entity;
    }

}
