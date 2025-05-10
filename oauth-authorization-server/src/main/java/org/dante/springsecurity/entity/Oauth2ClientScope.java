package org.dante.springsecurity.entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import javax.persistence.*;
import java.io.Serializable;
import java.util.UUID;

/**
 * 客户端权限范围
 *    1. 客户端能够请求哪些权限
 *    2. 授权码或令牌允许访问的 API 资源
 *    3. 控制数据访问级别
 *
 */
@Entity
@Table(name = "oauth2_client_scope")
@Data
@ToString(exclude = "client")
@EqualsAndHashCode(exclude = "client")
public class Oauth2ClientScope implements Serializable {

    @Id
    private String id;
    @ManyToOne
    @JoinColumn(name = "client_id")
    private Oauth2Client client;
    private String scope;   // read、write、delete

    public Oauth2ClientScope() {
        this.id = UUID.randomUUID().toString();
    }

    public static Oauth2ClientScope from(Oauth2Client client, String scope) {
        Oauth2ClientScope entity = new Oauth2ClientScope();
        entity.setClient(client);
        entity.setScope(scope);
        return entity;
    }

}
