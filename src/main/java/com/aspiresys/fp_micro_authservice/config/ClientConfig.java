package com.aspiresys.fp_micro_authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class ClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        /**
         * Client for the API Gateway
         * This client will be used by the API Gateway to authenticate and authorize requests
         * 
         * It uses the Client Credentials grant type, which is suitable for machine-to-machine communication.
         * The client ID is "fp_micro_gateway" and the secret
         * 
         * To configure the API Gateway to use this client, you will need to set the following properties:
         *   spring.security.oauth2.client.registration.fp_micro_gateway.client-id=fp_micro_gateway
         *  spring.security.oauth2.client.registration.fp_micro_gateway.client-secret=12345
         *  spring.security.oauth2.client.registration.fp_micro_gateway.authorization-grant-type=client_credentials
         *  spring.security.oauth2.client.registration.fp_micro_gateway.scope=gateway.read,gateway.write
         * Then the uri that the API Gateway will use to authenticate with the auth service will be:
         * http://localhost:8080/oauth2/token
         * This client will have the scopes "gateway.read" and "gateway.write"
         * 
         */
        RegisteredClient gatewayClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("fp_micro_gateway")
            .clientSecret("{noop}12345") 
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("gateway.read")
            .scope("gateway.write")
            .build();

        // Public client for frontend (React) with refresh token and PKCE enabled
        RegisteredClient reactClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("fp_frontend")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public, no secret
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Enable refresh tokens
            .redirectUri("http://localhost:3000/callback") // Change this according to your frontend URL
            .postLogoutRedirectUri("http://localhost:3000/") // URL after logout
            .scope("openid")
            .scope("profile")
            .scope("api.read")
            .scope("api.write")
            // Client configuration for PKCE
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false) // Don't require consent screen for own app
                .requireProofKey(true) // Require PKCE for security
                .build())
            // Token configuration
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(15)) // Access token valid for 15 minutes
                .refreshTokenTimeToLive(Duration.ofDays(30))   // Refresh token valid for 30 days
                .reuseRefreshTokens(false) // Generate new refresh token on each renewal
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(gatewayClient, reactClient);
    }
}

