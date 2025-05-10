package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2ClientScope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2ClientScopeDAO extends JpaRepository<Oauth2ClientScope, String> {
    
    void deleteByClientId(String clientId);
}
