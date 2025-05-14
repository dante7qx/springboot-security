package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2ClientTokenSettings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2ClientTokenSettingsDAO extends JpaRepository<Oauth2ClientTokenSettings, String> {
    
    void deleteByClientId(String clientId);
}
