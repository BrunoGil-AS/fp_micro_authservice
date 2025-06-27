package com.aspiresys.fp_micro_authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.*;
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

        // Cliente público para el frontend (React) con refresh token habilitado
        RegisteredClient reactClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("fp_frontend")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Público, sin secreto
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Habilitar refresh tokens
            .redirectUri("http://localhost:3000/callback") // Cambia esto según la URL de tu front
            .postLogoutRedirectUri("http://localhost:3000/") // URL después del logout
            .scope("openid")
            .scope("profile")
            .scope("api.read")
            .scope("api.write")
            // Configuración de tokens
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(15)) // Access token válido por 15 minutos
                .refreshTokenTimeToLive(Duration.ofDays(30))   // Refresh token válido por 30 días
                .reuseRefreshTokens(false) // Generar nuevo refresh token en cada renovación
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(gatewayClient, reactClient);
    }
}

