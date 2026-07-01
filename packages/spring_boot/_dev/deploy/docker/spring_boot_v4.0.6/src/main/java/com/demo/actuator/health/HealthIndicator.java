package com.demo.actuator.health;

import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.stereotype.Component;

// Spring Boot 4.0 modularized health contributors: AbstractHealthIndicator and
// Health moved from `org.springframework.boot.actuate.health` to
// `org.springframework.boot.health.contributor` (in the spring-boot-health module).
// An explicit bean name is required in SB 4 because the contributor name is
// derived by stripping the "HealthIndicator" suffix from the bean name and the
// class is literally named "HealthIndicator", leaving an empty contributor name.
@Component("app")
public class HealthIndicator extends AbstractHealthIndicator {

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
        // Use the builder to build the health status details that should be reported.
        // If you throw an exception, the status will be DOWN with the exception message.

        builder.up()
                .withDetail("app", "Alive and Kicking")
                .withDetail("error", "Nothing! I'm good.");
    }
}
