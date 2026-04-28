package com.asoc.app.model;

import java.time.Instant;
import java.util.List;

public record TrafficTelemetry(
        String requestId,
        String sourceIp,
        String path,
        String method,
        int statusCode,
        int requestCountLastMinute,
        double pathEntropy,
        double statusBurstScore,
        double repeatedPayloadScore,
        List<String> sqliTokenHits,
        String userAgent,
        String bodyPreview,
        Instant receivedAt
) {
}

