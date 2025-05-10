package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2ClientGrantType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2ClientGrantTypeDAO extends JpaRepository<Oauth2ClientGrantType, String> {
    
    void deleteByClientId(String clientId);
}
