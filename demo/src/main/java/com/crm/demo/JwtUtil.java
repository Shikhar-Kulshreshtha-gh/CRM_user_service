package com.crm.demo; // Change this to match your actual package name if different!

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    // A secure, randomly generated secret key for signing our tokens
    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // Token validity duration: 24 hours (in milliseconds)
    private final long EXPIRATION_TIME = 86400000;

    // 1. GENERATE TOKEN (When user logs in)
    public String generateToken(String email, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role); // Put the user's role into the token payload!

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key)
                .compact();
    }

    // 2. EXTRACT CLAIMS (Read data from an incoming token)
    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractEmail(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    // 3. VALIDATE TOKEN (Check if it has expired)
    public boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    public boolean validateToken(String token, String userEmail) {
        return (extractEmail(token).equals(userEmail) && !isTokenExpired(token));
    }
}