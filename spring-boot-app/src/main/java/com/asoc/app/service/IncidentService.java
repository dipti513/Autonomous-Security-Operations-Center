package com.asoc.app.service;

import com.asoc.app.model.IncidentView;
import com.asoc.app.model.TrafficTelemetry;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Service;

@Service
public class IncidentService {

    private final CopyOnWriteArrayList<TrafficTelemetry> recentTelemetry = new CopyOnWriteArrayList<>();

    public void record(TrafficTelemetry telemetry) {
        recentTelemetry.add(telemetry);
        while (recentTelemetry.size() > 200) {
            recentTelemetry.remove(0);
        }
    }

    public List<IncidentView> recentIncidents() {
        return recentTelemetry.stream()
                .sorted(Comparator.comparing(TrafficTelemetry::receivedAt).reversed())
                .map(item -> new IncidentView(item.requestId(), item.sourceIp(), item.path(), item.statusCode(), item.receivedAt()))
                .toList();
    }

    public int totalRequestsSeen() {
        return recentTelemetry.size();
    }
}

