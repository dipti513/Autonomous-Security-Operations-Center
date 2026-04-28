package com.asoc.app.service;

import com.asoc.app.config.AsocProperties;
import com.asoc.app.model.BlockIpRequest;
import com.asoc.app.model.BlockedIpRecord;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

@Service
public class FirewallService {

    private final Map<String, BlockedIpRecord> blockedIps = new ConcurrentHashMap<>();
    private final AsocProperties properties;

    public FirewallService(AsocProperties properties) {
        this.properties = properties;
    }

    public BlockedIpRecord block(BlockIpRequest request) {
        int ttlSeconds = request.ttlSeconds() != null ? request.ttlSeconds() : properties.defaultBlockTtlSeconds();
        Instant now = Instant.now();
        BlockedIpRecord record = new BlockedIpRecord(
                request.sourceIp(),
                request.incidentId(),
                request.reason(),
                request.confidence(),
                now,
                now.plusSeconds(ttlSeconds)
        );
        blockedIps.put(request.sourceIp(), record);
        return record;
    }

    public void unblock(String sourceIp) {
        blockedIps.remove(sourceIp);
    }

    public boolean isBlocked(String sourceIp) {
        expireOldEntries();
        return blockedIps.containsKey(sourceIp);
    }

    public List<BlockedIpRecord> listBlocked() {
        expireOldEntries();
        return blockedIps.values().stream()
                .sorted(Comparator.comparing(BlockedIpRecord::expiresAt))
                .toList();
    }

    private void expireOldEntries() {
        Instant now = Instant.now();
        blockedIps.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
    }
}

