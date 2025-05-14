package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2ClientSettings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Oauth2ClientSettingDAO extends JpaRepository<Oauth2ClientSettings, String> {
    
    void deleteByClientId(String clientId);
}
