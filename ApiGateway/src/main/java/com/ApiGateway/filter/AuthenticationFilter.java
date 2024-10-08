package com.ApiGateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import com.ApiGateway.util.JwtUtils;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Autowired
    private RouteValidator routeValidator;

    @Autowired
    private JwtUtils jwtUtils;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (routeValidator.isSecured.test(exchange.getRequest())) {

                // Check if Authorization header is present
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    logger.error("Authorization header missing");
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing authorization header");
                }

                // Extract the Authorization header
                String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                logger.info("Authorization Header: {}", authHeader);

                // Ensure the token follows the Bearer schema
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    String token = authHeader.substring(7); // Remove "Bearer " prefix
                    logger.info("Token extracted: {}", token);

                    try {
                        // Validate the JWT token
                        jwtUtils.validateToken(token);
                        logger.info("Token validation successful");

                        // Extract username from the token
                        String username = jwtUtils.extractUsername(token);
                        logger.info("JWT validated for user: {}", username);

                        // Add the username to the request headers
                        exchange = exchange.mutate()
                                .request(exchange.getRequest().mutate()
                                        .header("username", username)
                                        .build())
                                .build();

                        logger.info("Username {} added to request headers", username);

                    } catch (Exception e) {
                        logger.error("Invalid JWT token: {}", e.getMessage());
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid JWT token");
                    }

                } else {
                    logger.error("Authorization header does not contain Bearer token");
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authorization header must start with Bearer");
                }
            }

            // Continue with the request chain
            return chain.filter(exchange);
        });
    }

    // Configuration class (currently empty but required)
    public static class Config {
        // Add any configuration properties if needed
    }
}
