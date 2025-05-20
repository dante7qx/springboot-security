package org.dante.springsecurity.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

@Slf4j
@Service
public class SpiritOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser>  {

    private final OidcUserService oidcUserService = new OidcUserService();

    private final WebClient webClient;

    public SpiritOidcUserService(@Lazy WebClient webClient) {
        this.webClient = webClient;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("=========> 自定义的 SpiritOidcUserService registrationId -> {}", registrationId);

        return switch (registrationId) {
            case "google" -> handleGoogleOidcUser(userRequest);
            case "microsoftAzure" -> null;
            default -> handleSpiritOidcUser(userRequest);
        };
    }

    private OidcUser handleGoogleOidcUser(OidcUserRequest userRequest) {
        OidcUser oidcUser = oidcUserService.loadUser(userRequest);
        return new DefaultOidcUser(
                oidcUser.getAuthorities(),
                oidcUser.getIdToken(),
                oidcUser.getUserInfo(),
                IdTokenClaimNames.SUB
        );
    }

    private OidcUser handleSpiritOidcUser(OidcUserRequest userRequest) {
        OidcUser oidcUser = oidcUserService.loadUser(userRequest);
        var providerDetails = userRequest.getClientRegistration().getProviderDetails();
        //  远程调用 AS /userInfo
        Map<String, Object> userInfo = webClient
                .get()
                .uri(providerDetails.getUserInfoEndpoint().getUri())
                .headers(h -> h.setBearerAuth(userRequest.getAccessToken().getTokenValue()))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();

        return new DefaultOidcUser(
                oidcUser.getAuthorities(),
                oidcUser.getIdToken(),
                new OidcUserInfo(userInfo),
                IdTokenClaimNames.SUB
        );

    }
}
