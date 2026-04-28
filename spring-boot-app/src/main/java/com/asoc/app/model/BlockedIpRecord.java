package com.asoc.app.model;

import java.time.Instant;

public record BlockedIpRecord(
        String sourceIp,
        String incidentId,
        String reason,
        double confidence,
        Instant createdAt,
        Instant expiresAt
) {
}

