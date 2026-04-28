package com.asoc.app.web;

import com.asoc.app.model.BlockIpRequest;
import com.asoc.app.model.BlockedIpRecord;
import com.asoc.app.service.FirewallService;
import com.asoc.app.service.IncidentService;
import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final FirewallService firewallService;
    private final IncidentService incidentService;

    public AdminController(FirewallService firewallService, IncidentService incidentService) {
        this.firewallService = firewallService;
        this.incidentService = incidentService;
    }

    @PostMapping("/firewall/block")
    public BlockedIpRecord blockIp(@Valid @RequestBody BlockIpRequest request) {
        return firewallService.block(request);
    }

    @PostMapping("/firewall/unblock/{sourceIp}")
    public Map<String, String> unblockIp(@PathVariable String sourceIp) {
        firewallService.unblock(sourceIp);
        return Map.of("status", "unblocked", "sourceIp", sourceIp);
    }

    @GetMapping("/firewall/blocked")
    public List<BlockedIpRecord> blockedIps() {
        return firewallService.listBlocked();
    }

    @GetMapping("/incidents")
    public Object incidents() {
        return incidentService.recentIncidents();
    }

    @GetMapping("/system-health")
    public Map<String, Object> systemHealth() {
        return Map.of(
                "timestamp", Instant.now().toString(),
                "blockedIps", firewallService.listBlocked().size(),
                "observedRequests", incidentService.totalRequestsSeen(),
                "status", "defended"
        );
    }
}

