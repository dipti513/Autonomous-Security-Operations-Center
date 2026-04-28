package com.asoc.app.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "asoc")
public record AsocProperties(
        String adminToken,
        String orchestratorBaseUrl,
        int defaultBlockTtlSeconds
) {
}

