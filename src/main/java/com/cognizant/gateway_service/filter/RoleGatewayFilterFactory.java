package com.cognizant.gateway_service.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@Component
public class RoleGatewayFilterFactory extends AbstractGatewayFilterFactory<RoleGatewayFilterFactory.Config> {

    public RoleGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("role");
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String[] allowedRoles = config.getRole().split(",");
            System.out.println("RoleGatewayFilter: Processing request for " + exchange.getRequest().getURI());
            System.out.println("Allowed roles: " + Arrays.toString(allowedRoles));

            // Check if PUBLIC role is allowed (no authentication required)
            boolean isPublic = Arrays.stream(allowedRoles)
                    .map(String::trim)
                    .anyMatch(role -> role.equalsIgnoreCase("PUBLIC"));

            if (isPublic) {
                return chain.filter(exchange);
            }

            // For non-public endpoints, check authentication
            return ReactiveSecurityContextHolder.getContext()
                    .filter(c -> c.getAuthentication() != null)
                    .flatMap(c -> {
                        if (c.getAuthentication() instanceof JwtAuthenticationToken jwtToken) {
                            Jwt jwt = jwtToken.getToken();
                            String userRole = jwt.getClaimAsString("role");

                            boolean isAuthorized = Arrays.stream(allowedRoles)
                                    .map(String::trim)
                                    .anyMatch(role -> role.equalsIgnoreCase("ANY")
                                            || (userRole != null && role.equalsIgnoreCase(userRole)));

                            if (isAuthorized) {
                                return chain.filter(exchange);
                            }
                        }
                        return onError(exchange, HttpStatus.FORBIDDEN);
                    })
                    .switchIfEmpty(onError(exchange, HttpStatus.UNAUTHORIZED));
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
        private String role;

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }
}
