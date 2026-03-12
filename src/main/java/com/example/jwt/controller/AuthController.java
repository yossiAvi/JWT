package com.example.jwt.controller;

import com.example.jwt.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtService jwtService;

    public AuthController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * POST /auth/verify
     * Header: Authorization: Bearer <token>
     *
     * SSO check — validates the JWT signed with the shared secret key
     * and returns the decoded claims (user info) if valid.
     * Returns 401 if the token is invalid or expired.
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verifyToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Missing or malformed Authorization header",
                                 "expected", "Bearer <token>"));
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = jwtService.validateAndExtractClaims(token);

            Map<String, Object> result = new HashMap<>(claims);
            result.put("valid", true);
            result.put("username", claims.getSubject());
            result.put("issuedAt", claims.getIssuedAt());
            result.put("expiresAt", claims.getExpiration());

            return ResponseEntity.ok(result);

        } catch (JwtException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "valid", false,
                        "error", "Token validation failed",
                        "detail", e.getMessage()
                    ));
        }
    }
}
