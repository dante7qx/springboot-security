package org.dante.springsecurity.alipay;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.Data;

import java.util.Map;

@Data
@JsonDeserialize(using = AlipayRespDeserializer.class)
public class AlipayResp<T> {

    private T data;

    private String sign;


    public static void main(String[] args) throws JsonProcessingException {
        String json = """
                {
                 "alipay_user_info_share_response": {
                 "code": "10000",
                 "msg": "Success",
                 "age": "44",
                 "avatar": "https:\\/\\/tfs.alipayobjects.com\\/images\\/partner\\/https:\\/\\/mdn.alipayobjects.com\\/sandboxsys\\/afts\\/img\\/AibKQZxFsLUAAAAAAAAAAAAADgSLAQBr\\/original",
                 "cert_no": "417238197809170691",
                 "cert_type": "0",
                 "city": "资阳市",
                 "country_code": "CN",
                 "deliver_addresses": [{
                 "address_code": "512000",
                 "default_deliver_address": "F",
                 "deliver_city": "资阳市",
                 "deliver_province": "四川省"
                 }],
                 "display_name": "ookuoo7552@sandbox.com",
                 "email": "ookuooxxxx@sandbox.com",
                 "gender": "m",
                 "inst_or_corp": "N",
                 "is_blocked": "F",
                 "is_certified": "T",
                 "is_student_certified": "F",
                 "member_grade": "unknown",
                 "mobile": "10900000001",
                 "nick_name": "沙箱账号",
                 "person_birthday": "19780917",
                 "person_birthday_without_year": "0917",
                 "province": "四川省",
                 "user_id": "208872200175xxxx","open_id": "074a1CcTG1LelxKe4xQC0zgNdId0nxi95b5lsNpazWYoCo5",
                 "user_name": "ookuoo7552",
                 "user_status": "T",
                 "user_type": "2"
                 }
                }
                """;

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(json);
        JsonNode sign1 = rootNode.get("sign");
        JsonNode rsp = rootNode.get("alipay_user_info_share_response");
        Map<String, Object> stringObjectMap = objectMapper.convertValue(rsp, new TypeReference<Map<String, Object>>() {
        });
        System.out.println("======> " + stringObjectMap);
    }



}
