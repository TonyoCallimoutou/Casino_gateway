package com.casino.gateway.Config;

import com.casino.gateway.Utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebFluxSecurity
public class WebConfig {

  @Autowired
  private JwtUtils jwtUtils;

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration corsConfiguration = new CorsConfiguration();
    corsConfiguration.addAllowedOriginPattern("*"); // Permet tous les domaines. Remplacez par des domaines spécifiques en production.
    corsConfiguration.addAllowedMethod("*"); // Permet toutes les méthodes (GET, POST, PUT, DELETE, etc.).
    corsConfiguration.addAllowedHeader("*"); // Permet tous les en-têtes.
    corsConfiguration.setAllowCredentials(true); // Permet d'envoyer des cookies si nécessaire.

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", corsConfiguration); // Applique les règles à toutes les routes.
    return source;
  }

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    return http
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .authorizeExchange(exchanges -> exchanges
            .pathMatchers("/auth/**").permitAll()  // Pas de sécurité pour le service d'authentification
            .anyExchange().authenticated()
        )
        .addFilterAt((exchange, chain) -> {
          if (exchange.getRequest().getURI().getPath().startsWith("/auth")) {
            return chain.filter(exchange);
          }

          String token = jwtUtils.extractToken(exchange.getRequest().getHeaders());
          if (token == null) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
          }

          // Validation et extraction des informations du token
          return jwtUtils.validateToken(token)
              .flatMap(auth -> chain.filter(exchange)
                  .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)))
              .then(chain.filter(exchange));
        }, SecurityWebFiltersOrder.AUTHENTICATION)
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .build();
  }
}
