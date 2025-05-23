package org.dante.springsecurity.alipay;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Date;

@Data
public class OAuthTokenResp {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("auth_start")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date authStart;

    @JsonProperty("expires_in")
    private Long expiresIn;

    @JsonProperty("re_expires_in")
    private Long reExpiresIn;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("open_id")
    private String openId;



}
