package com.casino.gateway.Config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

@Configuration
@EnableWebFluxSecurity
public class GatewayConfig {

  @Bean
  public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
    return builder.routes()
        .route("auth_service", r -> r.path("/auth/**")
            .uri("http://localhost:8082"))
        .route("game_service", r -> r.path("/game/**")
            //.filters(f -> f.filter(new JwtAuthenticationFilter()))
            .uri("http://localhost:8081"))
        .build();
  }
}
