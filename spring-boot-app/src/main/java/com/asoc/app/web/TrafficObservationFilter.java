package com.asoc.app.web;

import com.asoc.app.model.TrafficTelemetry;
import com.asoc.app.service.IncidentService;
import com.asoc.app.service.TelemetryPublisher;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class TrafficObservationFilter extends OncePerRequestFilter {

    private final ConcurrentHashMap<String, AtomicInteger> requestCounters = new ConcurrentHashMap<>();
    private final IncidentService incidentService;
    private final TelemetryPublisher telemetryPublisher;

    public TrafficObservationFilter(IncidentService incidentService, TelemetryPublisher telemetryPublisher) {
        this.incidentService = incidentService;
        this.telemetryPublisher = telemetryPublisher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        filterChain.doFilter(request, response);

        String sourceIp = resolveClientIp(request);
        int currentRate = requestCounters.computeIfAbsent(sourceIp, ignored -> new AtomicInteger()).incrementAndGet();
        List<String> sqliTokens = detectSqlTokens(request);
        String path = request.getRequestURI();
        TrafficTelemetry telemetry = new TrafficTelemetry(
                UUID.randomUUID().toString(),
                sourceIp,
                path,
                request.getMethod(),
                response.getStatus(),
                currentRate,
                approximatePathEntropy(path),
                response.getStatus() >= 500 ? 0.9 : 0.2,
                sqliTokens.isEmpty() ? 0.15 : 0.88,
                sqliTokens,
                request.getHeader("User-Agent"),
                request.getQueryString() == null ? "" : request.getQueryString(),
                Instant.now()
        );
        incidentService.record(telemetry);
        telemetryPublisher.publish(telemetry);
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private List<String> detectSqlTokens(HttpServletRequest request) {
        List<String> hits = new ArrayList<>();
        String query = request.getQueryString();
        if (query == null) {
            return hits;
        }
        String lowered = query.toLowerCase();
        if (lowered.contains("' or 1=1")) {
            hits.add("' OR 1=1");
        }
        if (lowered.contains("union select")) {
            hits.add("UNION SELECT");
        }
        if (lowered.contains("drop table")) {
            hits.add("DROP TABLE");
        }
        return hits;
    }

    private double approximatePathEntropy(String path) {
        long distinctChars = path.chars().distinct().count();
        return Math.min(1.0, distinctChars / 24.0);
    }
}

