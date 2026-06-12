package com.demo.actuator;

import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Seeds the actuator at application startup so that the integration's system
 * tests reliably capture representative sample events on the first agent poll:
 *
 *   - Inserts a couple of synthetic {@code AUTHENTICATION_SUCCESS} audit events
 *     directly into the in-memory {@link AuditEventRepository}.
 *   - Performs a handful of authenticated self-requests against actuator
 *     endpoints, each of which is automatically recorded by the
 *     {@code httpexchanges} actuator endpoint's recording filter.
 */
@Component
public class StartupWarmup {

    private final AuditEventRepository auditEventRepository;

    public StartupWarmup(AuditEventRepository auditEventRepository) {
        this.auditEventRepository = auditEventRepository;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warmUp() {
        Map<String, Object> details = new HashMap<>();
        details.put("remoteAddress", "127.0.0.1");
        details.put("sessionId", "STARTUP-WARMUP-SESSION");
        auditEventRepository.add(new AuditEvent(Instant.now(), "actuator", "AUTHENTICATION_SUCCESS", details));
        auditEventRepository.add(new AuditEvent(Instant.now(), "actuator", "AUTHENTICATION_SUCCESS", details));

        try {
            RestClient client = RestClient.builder()
                    .baseUrl("http://localhost:8090")
                    // Basic actuator:actuator
                    .defaultHeader(HttpHeaders.AUTHORIZATION, "Basic YWN0dWF0b3I6YWN0dWF0b3I=")
                    .build();
            for (int i = 0; i < 3; i++) {
                client.get().uri("/actuator/health").retrieve().toBodilessEntity();
                client.get().uri("/actuator/info").retrieve().toBodilessEntity();
            }
        } catch (Exception ignored) {
            // best-effort; the synthetic audit events above already guarantee coverage.
        }
    }
}
