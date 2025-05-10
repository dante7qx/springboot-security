package org.dante.springsecurity.entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import javax.persistence.*;
import java.io.Serializable;
import java.util.UUID;

/**
 * 客户端认证方式表
 *
 */
@Entity
@Table(name = "oauth2_client_grant_type")
@Data
@ToString(exclude = "client")
@EqualsAndHashCode(exclude = "client")
public class Oauth2ClientGrantType implements Serializable {

    @Id
    private String id;
    @ManyToOne
    @JoinColumn(name = "client_id")
    private Oauth2Client client;
    private String grantType;   // authorization_code、client_credentials

    public Oauth2ClientGrantType() {
        this.id = UUID.randomUUID().toString();
    }

    public AuthorizationGrantType toGrantType() {
        return new AuthorizationGrantType(this.grantType);
    }

    public static Oauth2ClientGrantType from(Oauth2Client client, AuthorizationGrantType grantType) {
        Oauth2ClientGrantType entity = new Oauth2ClientGrantType();
        entity.setClient(client);
        entity.setGrantType(grantType.getValue());
        return entity;
    }

}
