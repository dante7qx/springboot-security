package org.dante.springsecurity.dao;

import org.dante.springsecurity.entity.Oauth2ClientKeypair;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface Oauth2ClientKeypairDAO extends JpaRepository<Oauth2ClientKeypair, String> {

    /**
     * 按客户端ID查找所有密钥（过期、未过期）
     */
    Optional<Oauth2ClientKeypair> findByClientId(String clientId);

    /**
     * 按客户端ID查找有效密钥（未过期）
     */
    @Query("select k from Oauth2ClientKeypair k where k.clientId = :clientId and k.expiresAt > :now")
    Optional<Oauth2ClientKeypair> findValidByClientId(@Param("clientId") String clientId, @Param("now") Instant now);

    // 查找所有有效密钥（用于JWK端点）
    @Query("SELECT k FROM Oauth2ClientKeypair k WHERE k.expiresAt > :now")
    List<Oauth2ClientKeypair> findValidKeys(@Param("now") Instant now);

    // 查找即将过期的密钥（用于轮换）
    @Query("SELECT k FROM Oauth2ClientKeypair k WHERE k.expiresAt BETWEEN :now AND :threshold")
    List<Oauth2ClientKeypair> findExpiringSoon(@Param("now") Instant now, @Param("threshold") Instant threshold);
}
