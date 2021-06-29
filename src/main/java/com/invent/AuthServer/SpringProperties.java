package com.invent.AuthServer;

import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@Configuration
@ConfigurationProperties(prefix = "spring")
public class SpringProperties {

    private String keyAlias;
    private String keystorePassword;
    private String keyPassword;

    private DataSource dataSource = new DataSource();

    @Data
    public class DataSource {
        private String url;
        private String username;
        private String password;
        private String driverClassName;
    }
}
