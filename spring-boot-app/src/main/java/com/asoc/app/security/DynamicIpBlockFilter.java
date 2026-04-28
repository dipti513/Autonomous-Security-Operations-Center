package com.asoc.app.security;

import com.asoc.app.service.FirewallService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class DynamicIpBlockFilter extends OncePerRequestFilter {

    private final FirewallService firewallService;

    public DynamicIpBlockFilter(FirewallService firewallService) {
        this.firewallService = firewallService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String sourceIp = resolveClientIp(request);
        if (firewallService.isBlocked(sourceIp)) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.getWriter().write("Request blocked by ASOC firewall.");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

