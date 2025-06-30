package com.aspiresys.fp_micro_authservice.config;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;

import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfig {

    /**
     * Specific configuration for OAuth2 Authorization Server.
     * This filter must have the highest ORDER to be processed first.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .securityMatcher("/oauth2/**", "/.well-known/**")
            .with(authorizationServerConfigurer, authorizationServer -> {
                authorizationServer
                    .oidc(Customizer.withDefaults())
                    .authorizationEndpoint(authorizationEndpoint -> 
                        authorizationEndpoint.consentPage("/oauth2/consent"));
            })
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(
                    (request, response, authException) -> {
                        System.out.println("Auth Server - Authentication error at: " + request.getRequestURI());
                        System.out.println("Auth Server - Exception: " + authException.getMessage());
                        response.sendRedirect("/login?error=unauthorized");
                    }
                )
            );

        System.out.println("=== AUTHORIZATION SERVER FILTER CHAIN CONFIGURED ===");
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
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/api/register").permitAll() // API registration endpoint
                .requestMatchers("/user/register").permitAll() // Web registration page
                .requestMatchers("/oauth2/consent").permitAll() // OAuth2 consent page
                .requestMatchers("/oauth2/server-info", "/oauth2/test-direct").permitAll() // OAuth2 info endpoints
                .requestMatchers("/error").permitAll() // Error handling page
                .requestMatchers("/login").permitAll() // Login page
                .requestMatchers("/css/**", "/js/**", "/images/**").permitAll() // Static resources
                .anyRequest().authenticated())
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/")
                .permitAll())
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout")
                .permitAll());

        return http.build();
    }

    // Password encoder (to save and verify hashed passwords)
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
            throw new IllegalStateException("Error generating RSA keys", ex);
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

    /**
     * Configures CORS (Cross-Origin Resource Sharing) for the application.
     * <p>
     * This bean sets up CORS to allow requests from specific origins, methods, and headers.
     * It allows credentials to be included in the requests, which is necessary for cookies and HTTP
     * authentication.
     * </p>
     * * @return a {@link CorsConfigurationSource} that provides the CORS configuration
     * <p>
     * This configuration allows requests from "http://localhost:3000" (the React frontend),
     * allows all HTTP methods, and allows all headers.
     * * Note: Adjust the allowed origin as necessary for your frontend application.
     * </p>
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("http://localhost:3000");
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Provides an OAuth2 Authorization Consent Service for storing user consent decisions.
     * <p>
     * This bean creates an in-memory service to store and retrieve user consent decisions
     * for OAuth2 authorization requests. In production, consider using a persistent storage.
     * </p>
     * 
     * @return an {@link OAuth2AuthorizationConsentService} for managing consent decisions
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    /**
     * Provides an OAuth2 Authorization Service for storing authorization codes and access tokens.
     * <p>
     * This bean creates an in-memory service to store and retrieve OAuth2 authorizations.
     * In production, consider using a persistent storage like database or Redis.
     * </p>
     * 
     * @return an {@link OAuth2AuthorizationService} for managing authorizations
     */
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }
}


