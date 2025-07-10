package com.aspiresys.fp_micro_authservice.controller;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;

/**
 * Controller providing endpoints for inspecting and testing the OAuth2 Authorization Server configuration.
 * <p>
 * Exposes endpoints to:
 * <ul>
 *   <li>Retrieve server and registered client information for diagnostics and verification.</li>
 *   <li>Test direct reachability of the authorization endpoint for troubleshooting routing issues.</li>
 * </ul>
 * <p>
 * Endpoints:
 * <ul>
 *   <li><b>GET /oauth2/server-info</b>: Returns details about the authorization server, its endpoints, and registered clients.</li>
 *   <li><b>GET /oauth2/test-direct</b>: Simple endpoint to verify controller reachability and provide guidance for testing the authorization endpoint.</li>
 * </ul>
 */
@RestController
@RequestMapping("/oauth2")
public class OAuth2InfoController {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    /**
     * Endpoint to verify Authorization Server configuration
     */
    @GetMapping("/server-info")
    public ResponseEntity<Map<String, Object>> serverInfo() {
        
        // Verify that clients are registered
        var frontendClient = registeredClientRepository.findByClientId("fp_frontend");
        var gatewayClient = registeredClientRepository.findByClientId("fp_micro_gateway");
        
        Map<String, Object> info = Map.of(
            "authorizationServer", "Spring Authorization Server",
            "issuer", "http://localhost:8081",
            "endpoints", Map.of(
                "authorization", "/oauth2/authorize",
                "token", "/oauth2/token",
                "jwks", "/oauth2/jwks",
                "userinfo", "/userinfo",
                "consent", "/oauth2/consent",
                "device_authorization", "/oauth2/device_authorization",
                "device_verification", "/oauth2/device_verification"
            ),
            "registeredClients", Map.of(
                "fp_frontend", frontendClient != null ? Map.of(
                    "clientId", frontendClient.getClientId(),
                    "scopes", frontendClient.getScopes(),
                    "redirectUris", frontendClient.getRedirectUris(),
                    "grantTypes", frontendClient.getAuthorizationGrantTypes().stream()
                        .map(grantType -> grantType.getValue()).toList()
                ) : "NOT FOUND",
                "fp_micro_gateway", gatewayClient != null ? Map.of(
                    "clientId", gatewayClient.getClientId(),
                    "scopes", gatewayClient.getScopes(),
                    "grantTypes", gatewayClient.getAuthorizationGrantTypes().stream()
                        .map(grantType -> grantType.getValue()).toList()
                ) : "NOT FOUND"
            ),
            "status", "Authorization Server is configured and running"
        );
        
        return ResponseEntity.ok(info);
    }

    /**
     * Endpoint to manually test the authorization endpoint
     */
    @GetMapping("/test-direct")
    public ResponseEntity<Map<String, Object>> testDirect() {
        Map<String, Object> response = Map.of(
            "message", "This endpoint is reachable",
            "note", "If /oauth2/authorize returns 404, there's a routing issue",
            "suggestion", "Try accessing /oauth2/authorize with proper parameters",
            "example", "/oauth2/authorize?response_type=code&client_id=fp_frontend&redirect_uri=http://localhost:3000/callback&scope=openid&code_challenge=test&code_challenge_method=S256"
        );
        
        return ResponseEntity.ok(response);
    }
}
