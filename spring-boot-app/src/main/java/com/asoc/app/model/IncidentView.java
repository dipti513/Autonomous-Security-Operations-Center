package com.asoc.app.model;

import java.time.Instant;

public record IncidentView(
        String requestId,
        String sourceIp,
        String path,
        int statusCode,
        Instant receivedAt
) {
}

