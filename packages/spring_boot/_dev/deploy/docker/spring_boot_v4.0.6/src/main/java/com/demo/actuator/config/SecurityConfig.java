package com.demo.actuator.config;

import org.springframework.boot.actuate.context.ShutdownEndpoint;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.boot.security.autoconfigure.web.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

// Spring Security 6 (Spring Boot 3.0) removed WebSecurityConfigurerAdapter.
// Configuration is now done by exposing a SecurityFilterChain bean and
// requestMatchers() replaces antMatchers().
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(EndpointRequest.to(ShutdownEndpoint.class)).hasRole("ACTUATOR_ADMIN")
                .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                .requestMatchers("/", "/slowApi").permitAll()
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
