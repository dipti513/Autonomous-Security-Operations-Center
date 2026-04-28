package com.asoc.app.model;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record BlockIpRequest(
        @NotBlank String sourceIp,
        @NotBlank String incidentId,
        @NotBlank String reason,
        @NotNull Double confidence,
        @Min(60) @Max(86400) Integer ttlSeconds
) {
}

