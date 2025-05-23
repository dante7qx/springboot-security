package org.dante.springsecurity.alipay;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.lang.Console;
import cn.hutool.core.util.StrUtil;
import cn.hutool.core.util.URLUtil;
import cn.hutool.crypto.SignUtil;
import cn.hutool.crypto.asymmetric.Sign;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.TreeMap;

@Controller
@RequestMapping("/alipay")
public class AliPayController {

    private final AlipayClientProp config;
    private final WebClient webClient;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public AliPayController(AlipayClientProp config, @Qualifier("alipayWebClient") WebClient webClient) {
        this.config = config;
        this.webClient = webClient;
    }

    /**
     * 获取 AuthCode
     */
    @GetMapping("/oauth2/authorization")
    public void authorization(HttpServletResponse response) throws IOException {
        Console.log("========> 1. Alipay 授权请求");
        String appId = "2021000148695962";
        String redirectUri = "https://6f37a4f0.r21.cpolar.top/client/alipay/oauth2/code/callback";

        String scope = "auth_user,auth_base";
        // 拼接请求 uri。 https://openauth-sandbox.dl.alipaydev.com/oauth2/publicAppAuthorize.htm?app_id=APPID&scope=SCOPE&redirect_uri=ENCODED_URL
        String authorizeUrl = "https://openauth-sandbox.dl.alipaydev.com/oauth2/publicAppAuthorize.htm?app_id=" + appId + "&scope=" + scope + "&redirect_uri=" + URLUtil.encodeAll(redirectUri);
        response.sendRedirect(authorizeUrl);
    }

    /**
     * 获取 AccessToken
     */
    @SneakyThrows
    @GetMapping("/oauth2/code/callback")
    public String callback(HttpServletRequest request, HttpServletResponse response) {
        String code = request.getParameter("auth_code");
        Console.log("========> 2. 通过 auth_code {} 换取 access_token", code);

        Map<String, String> params = buildCommonParams("alipay.system.oauth.token");
        params.put("code", code);
        params.put("grant_type", "authorization_code");

        String respJson = webClient.post()
                .header("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
                .body(BodyInserters.fromFormData(buildForm(params)))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        AlipayResp<OAuthTokenResp> oAuthTokenResp = objectMapper.readValue(respJson, new TypeReference<AlipayResp<OAuthTokenResp>>() {});
        Console.log("{}\n{}", respJson, oAuthTokenResp);

        // 使用支付宝公钥对返回的 Sign 进行验签操作
        return "redirect:/alipay/userinfo/" + oAuthTokenResp.getData().getAccessToken();
    }

    /**
     * 支付宝会员授权信息查询
     */
    @GetMapping("/userinfo/{accessToken}")
    public String userInfo(@PathVariable("accessToken") String accessToken, Model model) throws JsonProcessingException {
        Console.log("========> 3. 通过 access_token {} 换取 access_token", accessToken);
        Map<String, String> params = buildCommonParams("alipay.user.info.share");
        params.put("auth_token", accessToken);
        String respJson = webClient.post()
                .header("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
                .body(BodyInserters.fromFormData(buildForm(params)))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        JsonNode rootNode = objectMapper.readTree(respJson);
        // 使用支付宝公钥对返回的 Sign 进行验签操作

        JsonNode dataNode = rootNode.get("alipay_user_info_share_response");
        model.addAttribute("userName", dataNode.get("display_name"));
        model.addAttribute("userAttributes", objectMapper.convertValue(dataNode, new TypeReference<Map<String, Object>>() {}));
        return "home";
    }



    /**
     * 签名请求参数
     */
    @SneakyThrows
    private String sign(String paramUrl) {
        if (paramUrl == null || paramUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Parameter URL cannot be null or empty");
        }
        Sign sign = SignUtil.sign(SignAlgorithm.SHA256withRSA, config.getPrivateKey(), null);
        return Base64.encode(sign.sign(paramUrl, StandardCharsets.UTF_8));
    }

    /**
     * 公共请求参数
     */
    private Map<String, String> buildCommonParams(String method) {
        Map<String, String> params = new TreeMap<>();
        params.put("app_id", config.getAppId());
        params.put("method", method);
        params.put("format", config.getFormat());
        params.put("charset", config.getCharset());
        params.put("sign_type", config.getSignType());
        params.put("timestamp", ZonedDateTime.now(ZoneId.of("Asia/Shanghai"))
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        params.put("version", config.getVersion());
        return params;
    }

    private MultiValueMap<String, String> buildForm(Map<String, String> params) {
        String signContent = params.entrySet()
                .stream()
                .filter(e -> StrUtil.isNotEmpty(e.getValue()))
                .map(e -> e.getKey() + "=" + e.getValue())
                .reduce((a, b) -> a + "&" + b)
                .orElse("");
        String sign = sign(signContent);
        Console.log("{}\n{}", signContent, sign);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        params.forEach(form::add);
        form.add("sign", sign);
        return form;
    }

}
