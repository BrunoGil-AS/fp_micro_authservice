package com.aspiresys.fp_micro_authservice.config;

import com.aspiresys.fp_micro_authservice.user.MyUserDetailsService;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration

public class SecurityConfig {

    
    /**
     * Configures the security filter chain for the OAuth2 Authorization Server endpoints.
     * <p>
     * This bean sets up security specifically for the endpoints exposed by the OAuth2 Authorization Server,
     * using the {@link OAuth2AuthorizationServerConfigurer}. It applies security rules only to the endpoints
     * matched by the authorization server such as:
     * <ul>
     *     <li>/oauth2/authorize: Authorization endpoint for user login and consent</li>
     *     <li>/oauth2/token: Token endpoint for exchanging authorization codes or credentials for access tokens</li>
     *     <li>/oauth2/token/introspect: Endpoint for introspecting access tokens</li>
     *     <li>/oauth2/token/revoke: Endpoint for revoking access tokens</li>
     *     <li>/oauth2/device_authorization: Endpoint for device authorization flow</li>
     *     <li>/oauth2/device_code: Endpoint for device code verification</li>
     *     <li>/oauth2/jwks: Endpoint for serving JSON Web Key Set (JWK) for public key retrieval</li>
     *     <li>/oauth2/oidc: OpenID Connect endpoints for user info and discovery</li>
     * </ul>
     * <p>
     * The configuration also enables OpenID Connect (OIDC) support by default, allowing the server to handle
     * OIDC requests if needed. If OIDC is not required, the related line can be removed.
     *
     * @param http the {@link HttpSecurity} to modify
     * @return the configured {@link SecurityFilterChain} for the authorization server endpoints
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, authorizationServer -> {
                authorizationServer.oidc(Customizer.withDefaults()); // Puedes quitar esto si no usas OpenID Connect
            });

        return http.build();
    }

    /**
     * Configures the default security filter chain for the application.
     * <p>
     * This bean sets up security for all other endpoints not covered by the OAuth2 Authorization Server.
     * It requires authentication for any request and provides a form-based login mechanism.
     * </p>
     *
     * @param http the {@link HttpSecurity} to modify
     * @return the configured {@link SecurityFilterChain} for the default application endpoints
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    // Servicio de usuarios personalizado (inyectado desde tu implementación)
    //@Bean
    //@Primary
    //public UserDetailsService userDetailsService(MyUserDetailsService uds) {
    //    return uds;
    //}

    // Codificador de contraseñas (para guardar y verificar contraseñas hasheadas)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Provides a JWK source for the OAuth2 Authorization Server.
     * <p>
     * This bean generates a new RSA key pair and creates a JWK set containing the public key,
     * which is used to sign JWT tokens issued by the authorization server.
     * </p>
     *
     * @return a {@link JWKSource} that provides the JWK set for the authorization server
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID(UUID.randomUUID().toString())
            .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Generates a new RSA key pair for signing JWT tokens.
     * <p>
     * This method creates a 2048-bit RSA key pair, which is used to sign the JWT tokens issued by the authorization server.
     * </p>
     *
     * @return a {@link KeyPair} containing the generated RSA public and private keys
     */
    private KeyPair generateRsaKey() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Error al generar claves RSA", ex);
        }
    }
    /**
     * Customizer for JWT tokens to include user roles in the access token.
     * <p>
     * This bean customizes the JWT encoding context to add a "roles" claim
     * containing the user's roles, which are derived from their authorities.
     * </p>
     *
     * @return an {@link OAuth2TokenCustomizer} that modifies the JWT claims
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if ("access_token".equals(context.getTokenType().getValue())) {
                Set<String> roles = context.getPrincipal().getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

                context.getClaims().claim("roles", roles);
            }
        };
    }
}


