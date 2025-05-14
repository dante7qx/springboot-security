package org.dante.springsecurity.controller;

import lombok.RequiredArgsConstructor;
import org.dante.springsecurity.dto.Oauth2ClientDTO;
import org.dante.springsecurity.service.Oauth2RegisteredClientService;
import org.springframework.http.HttpEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 客户端 Controller
 */
@RestController
@RequestMapping("/oauth2_client")
@RequiredArgsConstructor
public class Oauth2ClientController {

    private final Oauth2RegisteredClientService clientService;

    /**
     * 注册新客户端
     */
    @PostMapping("/register")
    public HttpEntity<Integer> registerClient(@RequestBody Oauth2ClientDTO clientDTO) {
        clientService.save(clientDTO.toRegisteredClient());
        return new HttpEntity<>(1);
    }

}
