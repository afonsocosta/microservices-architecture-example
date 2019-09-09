package br.com.devaoc.core.property;

import lombok.Data;
import lombok.Getter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt.config")
@Data
@ToString
public class JwtConfiguration {
    private String loginUrl = "/login/**";
    @NestedConfigurationProperty
    private Header header = new Header();
    private int expiration = 3600;
    private String privateKey = "zKREemqJ5BaWvZ0btHG1jaSjl7ApVwc5";
    private String type = "encrypted";

    @Data
    public static class Header {
        private String name = "Authorization";
        private String prefix = "Bearer ";
    }

}
