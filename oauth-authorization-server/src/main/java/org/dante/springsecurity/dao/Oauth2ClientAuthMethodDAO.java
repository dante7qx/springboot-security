package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2ClientAuthMethod;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2ClientAuthMethodDAO extends JpaRepository<Oauth2ClientAuthMethod, String> {
    
    void deleteByClientId(String clientId);
}
