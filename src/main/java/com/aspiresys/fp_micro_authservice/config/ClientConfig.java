package com.aspiresys.fp_micro_authservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

import static com.aspiresys.fp_micro_authservice.config.AuthConstants.*;

/**
 * <h2>ClientConfig</h2>
 * <p>
 * Spring {@link org.springframework.context.annotation.Configuration} class responsible for registering OAuth2 clients
 * for the authentication service. This configuration defines two main clients:
 * </p>
 *
 * <ul>
 *   <li>
 *     <b>API Gateway Client</b>
 *     <ul>
 *       <li>
 *         <b>Client ID:</b> <code>fp_micro_gateway</code>
 *       </li>
 *       <li>
 *         <b>Grant Type:</b> Client Credentials (<code>client_credentials</code>)
 *       </li>
 *       <li>
 *         <b>Scopes:</b> <code>gateway.read</code>, <code>gateway.write</code>
 *       </li>
 *       <li>
 *         <b>Authentication:</b> Uses client secret (for machine-to-machine communication)
 *       </li>
 *       <li>
 *         <b>Usage:</b> Intended for the API Gateway to authenticate and authorize requests.
 *       </li>
 *     </ul>
 *   </li>
 *   <li>
 *     <b>Frontend (React) Client</b>
 *     <ul>
 *       <li>
 *         <b>Client ID:</b> <code>fp_frontend</code>
 *       </li>
 *       <li>
 *         <b>Grant Types:</b> Authorization Code (<code>authorization_code</code>) with PKCE, and Refresh Token
 *       </li>
 *       <li>
 *         <b>Scopes:</b> <code>openid</code>, <code>profile</code>, <code>api.read</code>, <code>api.write</code>
 *       </li>
 *       <li>
 *         <b>Authentication:</b> Public client (no client secret)
 *       </li>
 *       <li>
 *         <b>Security:</b> PKCE required for enhanced security
 *       </li>
 *       <li>
 *         <b>Token Settings:</b> Access tokens valid for 15 minutes, refresh tokens valid for 30 days, refresh tokens are not reused
 *       </li>
 *       <li>
 *         <b>Redirect URIs:</b> Configured dynamically from <code>service.env.frontend.server</code> property
 *       </li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <p>
 * <b>Note:</b> This configuration uses an in-memory repository for registered clients. For production environments,
 * consider using a persistent storage implementation.
 * </p>
 *
 * @author bruno.gil
 * @see org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
 * @see org.springframework.security.oauth2.server.authorization.client.RegisteredClient
 * @see org.springframework.security.oauth2.core.AuthorizationGrantType
 * @see org.springframework.security.oauth2.core.ClientAuthenticationMethod
 */
@Configuration
public class ClientConfig {
    @Value("${service.env.frontend.server}")
    private String frontendUrl;
    @Value("${service.env.auth.client.secret}")
    private String authClientSecret;
    /**
         * <h3>Client for the API Gateway</h3>
         * <p>
         * This client will be used by the API Gateway to authenticate and authorize requests.
         * </p>
         * <ul>
         *   <li>
         *     It uses the <b>Client Credentials</b> grant type, which is suitable for machine-to-machine communication.
         *   </li>
         *   <li>
         *     The client ID is <code>fp_micro_gateway</code> and the secret.
         *   </li>
         * </ul>
         * <p>
         * To configure the API Gateway to use this client, you will need to set the following properties:
         * </p>
         * <pre>
         * spring.security.oauth2.client.registration.fp_micro_gateway.client-id=fp_micro_gateway
         * spring.security.oauth2.client.registration.fp_micro_gateway.client-secret=12345
         * spring.security.oauth2.client.registration.fp_micro_gateway.authorization-grant-type=client_credentials
         * spring.security.oauth2.client.registration.fp_micro_gateway.scope=gateway.read,gateway.write
         * </pre>
         * <p>
         * Then the URI that the API Gateway will use to authenticate with the auth service will be:
         * <br>
         * <code>http://localhost:8080/oauth2/token</code>
         * </p>
         * <p>
         * This client will have the scopes <code>gateway.read</code> and <code>gateway.write</code>.
         * </p>
         */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient gatewayClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(CLIENT_ID_GATEWAY)
            .clientSecret(authClientSecret) 
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope(SCOPE_GATEWAY_READ)
            .scope(SCOPE_GATEWAY_WRITE)
            .build();

        // Public client for frontend (React) with refresh token and PKCE enabled
        RegisteredClient reactClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(CLIENT_ID_FRONTEND)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public, no secret
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // Enable refresh tokens
            .redirectUri(frontendUrl + REDIRECT_PATH)
            .postLogoutRedirectUri(frontendUrl) // URL after logout
            .scope(SCOPE_OPENID)
            .scope(SCOPE_PROFILE)
            .scope(SCOPE_API_READ)
            .scope(SCOPE_API_WRITE)
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

