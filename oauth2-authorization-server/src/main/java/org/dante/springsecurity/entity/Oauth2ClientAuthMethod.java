package org.dante.springsecurity.entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import javax.persistence.*;
import java.io.Serializable;
import java.util.UUID;

/**
 * 客户端认证方式表
 *
 */
@Entity
@Table(name = "oauth2_client_auth_method")
@Data
@ToString(exclude = "client")
@EqualsAndHashCode(exclude = "client")
public class Oauth2ClientAuthMethod implements Serializable {

    @Id
    private String id;
    @ManyToOne
    @JoinColumn(name = "client_id")
    private Oauth2Client client;
    private String method;

    public Oauth2ClientAuthMethod() {
        this.id = UUID.randomUUID().toString();
    }

    public ClientAuthenticationMethod toMethod() {
        return new ClientAuthenticationMethod(this.method);
    }

    public static Oauth2ClientAuthMethod from(Oauth2Client client, ClientAuthenticationMethod method) {
        Oauth2ClientAuthMethod entity = new Oauth2ClientAuthMethod();
        entity.setClient(client);
        entity.setMethod(method.getValue());
        return entity;
    }

}
