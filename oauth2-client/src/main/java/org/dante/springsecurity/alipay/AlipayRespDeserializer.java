package org.dante.springsecurity.alipay;


import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

/**
 * 自定义反序列化
 */
public class AlipayRespDeserializer extends JsonDeserializer<AlipayResp<?>> implements ContextualDeserializer {

    private final JavaType valueType; // 泛型 T

    public AlipayRespDeserializer() {
        this.valueType = null;
    }

    public AlipayRespDeserializer(JavaType valueType) {
        this.valueType = valueType;
    }

    @Override
    public JsonDeserializer<?> createContextual(DeserializationContext ctxt, BeanProperty property) {
        JavaType contextualType = ctxt.getContextualType(); // AlipayResp<T>
        JavaType valueType = contextualType.containedType(0); // 获取 T
        return new AlipayRespDeserializer(valueType);
    }

    @Override
    public AlipayResp<?> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
        ObjectMapper mapper = (ObjectMapper) p.getCodec();
        JsonNode rootNode = mapper.readTree(p);

        String sign = rootNode.path("sign").asText();

        // 找到业务字段（唯一一个非 sign 的字段）
        JsonNode dataNode = null;
        Iterator<Map.Entry<String, JsonNode>> fields = rootNode.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            if (!"sign".equals(entry.getKey())) {
                dataNode = entry.getValue();
                break;
            }
        }

        Object data = mapper.convertValue(dataNode, valueType);

        AlipayResp<Object> resp = new AlipayResp<>();
        resp.setData(data);
        resp.setSign(sign);
        return resp;
    }
}
