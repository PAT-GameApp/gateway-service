package com.cognizant.gateway_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .authorizeExchange(exchanges -> exchanges
                        // Allow all requests through the security filter chain
                        // The RoleGatewayFilter will handle authentication/authorization
                        .anyExchange().permitAll())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                        // Don't fail on invalid tokens for PUBLIC endpoints
                        // Let the RoleGatewayFilter decide what to do
                        .authenticationEntryPoint((exchange, ex) -> {
                            // Just continue - let the Role filter handle authorization
                            return Mono.empty();
                        }));
        return http.build();
    }
}
