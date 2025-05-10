package org.dante.springsecurity.dao;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.lang.Console;
import org.dante.springsecurity.entity.Oauth2Client;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DataJpaTest
class Oauth2ClientDaoTests  {

    @Autowired
    private Oauth2ClientDAO oauth2ClientDao;

    @Test
    void testCrud() {
        Console.log("======================== 测试开始 ==========================");
        Oauth2Client client1 = new Oauth2Client();
        client1.setClientId("client1");
        client1.setClientSecret("clientSecret1");
        client1.setIssuedAt(Instant.now());
        client1.setExpiresAt(DateUtil.endOfMonth(DateUtil.date()).toInstant());

        Oauth2Client client2 = new Oauth2Client();
        client2.setClientId("client2");
        client2.setClientSecret("clientSecret2");
        client2.setIssuedAt(Instant.now());
        client2.setExpiresAt(DateUtil.endOfMonth(DateUtil.date()).toInstant());

        oauth2ClientDao.saveAll(List.of(client1, client2));

        Optional<Oauth2Client> client = oauth2ClientDao.findByClientId("client2");

        Console.log(client.orElse(null));

        oauth2ClientDao.deleteAll();

        long count = oauth2ClientDao.count();

        assertEquals(0, count);

        Console.log("======================== 测试结束 ==========================");
    }

}
