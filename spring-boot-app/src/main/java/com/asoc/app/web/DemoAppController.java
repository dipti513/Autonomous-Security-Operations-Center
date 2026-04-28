package com.asoc.app.web;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/public")
public class DemoAppController {

    @GetMapping("/healthz")
    public Map<String, String> healthz() {
        return Map.of("status", "ok");
    }

    @GetMapping("/echo")
    public Map<String, String> echo(@RequestParam(defaultValue = "guest") String name) {
        return Map.of("message", "Hello " + name + ", your request passed through the protected app.");
    }
}

