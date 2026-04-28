package com.asoc.app;

import com.asoc.app.config.AsocProperties;
import com.asoc.app.model.BlockIpRequest;
import com.asoc.app.service.FirewallService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class FirewallServiceTest {

    @Test
    void blockAndUnblockFlowWorks() {
        FirewallService service = new FirewallService(new AsocProperties("token", "http://localhost:8000", 900));
        service.block(new BlockIpRequest("203.0.113.7", "incident-1", "test", 0.95, 120));
        Assertions.assertTrue(service.isBlocked("203.0.113.7"));
        service.unblock("203.0.113.7");
        Assertions.assertFalse(service.isBlocked("203.0.113.7"));
    }
}
