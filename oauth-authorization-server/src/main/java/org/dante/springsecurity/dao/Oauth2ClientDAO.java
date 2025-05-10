package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface Oauth2ClientDAO extends JpaRepository<Oauth2Client, String> {

    Optional<Oauth2Client> findByClientId(String clientId);
}
