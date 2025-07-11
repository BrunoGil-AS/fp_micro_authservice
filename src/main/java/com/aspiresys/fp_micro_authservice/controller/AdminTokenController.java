package com.aspiresys.fp_micro_authservice.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.java.Log;

import static com.aspiresys.fp_micro_authservice.config.AuthConstants.*;

/**
 * Controller responsible for generating admin tokens for gateway access.
 * <p>
 * This controller provides a secured endpoint that allows administrators to obtain
 * JWT tokens with admin privileges for accessing the gateway and other services.
 * The endpoint is restricted to users with ADMIN role only.
 * </p>
 *
 * <ul>
 *   <li><b>POST /admin/token</b>: Generates a JWT token with admin privileges.
 *       Only accessible by users with ROLE_ADMIN.</li>
 * </ul>
 *
 * Dependencies:
 * <ul>
 *   <li>{@link JwtEncoder} for creating and signing JWT tokens.</li>
 * </ul>
 *
 * Security:
 * <ul>
 *   <li>Endpoint is protected with {@code @PreAuthorize("hasRole('ADMIN')")}.</li>
 *   <li>Generated tokens include user roles and have a configurable expiration time.</li>
 * </ul>
 */
@RestController
@RequestMapping("/admin")
@Log
public class AdminTokenController {

    @Autowired
    private JwtEncoder jwtEncoder;

    /**
     * Generates a JWT token for admin users to access the gateway.
     * <p>
     * This endpoint creates a JWT token with the following claims:
     * <ul>
     *   <li>Subject: The authenticated user's name</li>
     *   <li>Audience: Gateway client ID</li>
     *   <li>Roles: User's authorities/roles</li>
     *   <li>Scopes: Gateway read and write permissions</li>
     *   <li>Expiration: 1 hour from creation</li>
     * </ul>
     * </p>
     *
     * @param authentication The current authentication context containing user details
     * @return ResponseEntity containing the JWT token or error message
     */
    @PostMapping("/token")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> generateAdminToken(Authentication authentication) {
        try {
            log.info("Admin token requested by user: " + authentication.getName());
            
            // Extract user roles
            Set<String> roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            
            // Validate that user has admin role
            if (!roles.contains(ROLE_ADMIN)) {
                log.warning("Token request denied: User " + authentication.getName() + " does not have admin role");
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new TokenResponse(null, "Access denied: Admin role required"));
            }
            
            // Create JWT claims
            Instant now = Instant.now();
            Instant expiration = now.plus(1, ChronoUnit.HOURS); // Token valid for 1 hour
            
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("http://auth-service:8080") // Auth service issuer
                    .subject(authentication.getName())
                    .audience(List.of(CLIENT_ID_GATEWAY, CLIENT_ID_FRONTEND))
                    .issuedAt(now)
                    .expiresAt(expiration)
                    .claim(CLAIM_ROLES, roles)
                    .claim("scope", SCOPE_GATEWAY_READ + " " + SCOPE_GATEWAY_WRITE + " " + SCOPE_API_READ + " " + SCOPE_API_WRITE)
                    .claim("token_type", "admin_access")
                    .build();
            
            // Create JWT header
            JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
            
            // Encode the token
            String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
            
            log.info("Admin token generated successfully for user: " + authentication.getName());
            
            return ResponseEntity.ok(new TokenResponse(token, "Admin token generated successfully"));
            
        } catch (Exception e) {
            log.severe("Error generating admin token for user " + authentication.getName() + ": " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new TokenResponse(null, "Error generating token: " + e.getMessage()));
        }
    }
    
    /**
     * Response DTO for token generation requests.
     */
    public static class TokenResponse {
        private String token;
        private String message;
        
        public TokenResponse(String token, String message) {
            this.token = token;
            this.message = message;
        }
        
        public String getToken() {
            return token;
        }
        
        public void setToken(String token) {
            this.token = token;
        }
        
        public String getMessage() {
            return message;
        }
        
        public void setMessage(String message) {
            this.message = message;
        }
    }
}
