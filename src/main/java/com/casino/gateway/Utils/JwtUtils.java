package com.casino.gateway.Utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

  private static final String SECRET_KEY = "c29tZXJhbmRvbGJhc2U2NGVuY29kZWRrZXk=";

  private static SecretKey getSignInKey() {
    byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public Claims getClaimFromToken(String token) {
    return Jwts.parser()
        .verifyWith(getSignInKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  public Mono<UsernamePasswordAuthenticationToken> validateToken(String token) {
    try {
      Claims claims = getClaimFromToken(token);

      List<SimpleGrantedAuthority> authorities = new ArrayList<>();

      if(! CollectionUtils.isEmpty( (List<?>) claims.get("roles"))) {
        authorities = ((List<?>) claims.get("roles")).stream()
            .map(role -> new SimpleGrantedAuthority(role.toString()))
            .collect(Collectors.toList());
      }

      return Mono.just(new UsernamePasswordAuthenticationToken(
          claims.getSubject(), null, authorities));
    } catch (Exception e) {
      return Mono.empty();
    }
  }

  public String extractToken(HttpHeaders headers) {
    String bearerToken = headers.getFirst(HttpHeaders.AUTHORIZATION);
    return (bearerToken != null && bearerToken.startsWith("Bearer ")) ? bearerToken.substring(7) : null;
  }

  public boolean isTokenExpired(Claims claims) {
    return claims.getExpiration().before(new Date());
  }

}