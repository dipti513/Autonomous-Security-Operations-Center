package com.asoc.app;

import com.asoc.app.config.AsocProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AsocProperties.class)
public class AsocProtectedApplication {

    public static void main(String[] args) {
        SpringApplication.run(AsocProtectedApplication.class, args);
    }
}

