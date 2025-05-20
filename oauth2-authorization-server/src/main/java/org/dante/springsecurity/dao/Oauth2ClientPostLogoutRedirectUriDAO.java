package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2ClientPostLogoutRedirectUri;
import org.dante.springsecurity.entity.Oauth2ClientRedirectUri;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2ClientPostLogoutRedirectUriDAO extends JpaRepository<Oauth2ClientPostLogoutRedirectUri, String> {
    
    void deleteByClientId(String clientId);
}
