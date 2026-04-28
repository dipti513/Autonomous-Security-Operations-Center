package com.asoc.app.service;

import com.asoc.app.config.AsocProperties;
import com.asoc.app.model.TrafficTelemetry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class TelemetryPublisher {

    private static final Logger log = LoggerFactory.getLogger(TelemetryPublisher.class);

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AsocProperties properties;

    public TelemetryPublisher(AsocProperties properties) {
        this.properties = properties;
    }

    public void publish(TrafficTelemetry telemetry) {
        try {
            String json = objectMapper.writeValueAsString(telemetry);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(properties.orchestratorBaseUrl() + "/events/traffic"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();
            httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .exceptionally(error -> {
                        log.warn("Unable to publish traffic telemetry to orchestrator: {}", error.getMessage());
                        return null;
                    });
        } catch (Exception error) {
            log.warn("Failed to serialize or publish telemetry: {}", error.getMessage());
        }
    }
}

