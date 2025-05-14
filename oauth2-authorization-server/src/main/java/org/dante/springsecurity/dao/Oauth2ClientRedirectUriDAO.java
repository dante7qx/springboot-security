package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2ClientRedirectUri;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2ClientRedirectUriDAO extends JpaRepository<Oauth2ClientRedirectUri, String> {
    
    void deleteByClientId(String clientId);
}
