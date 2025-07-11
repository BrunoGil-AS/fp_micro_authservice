package com.aspiresys.fp_micro_authservice.config;

/**
 * <p>
 * The {@code AuthConstants} class contains constant values used throughout the authentication service.
 * These constants include client IDs, OAuth2 scopes, redirect URIs, user roles, initial admin credentials,
 * JWT claim names, and arrays of public endpoint paths.
 * </p>
 *
 * <h2>Usage</h2>
 * <ul>
 *   <li>Reference client IDs for OAuth2 client configuration.</li>
 *   <li>Use scope constants for defining and validating OAuth2 scopes.</li>
 *   <li>Utilize role constants for role-based access control.</li>
 *   <li>Access public endpoint arrays to configure security filters for unauthenticated access.</li>
 *   <li>Initial admin credentials are used for the first-time setup and should be changed in production.</li>
 * </ul>
 *
 * <p>
 * This class is not intended to be instantiated.
 * </p>
 * 
 * @author Bruno Gil
 * @version 1.0
 * @since 1.0
 */
public final class AuthConstants {
    private AuthConstants() {}

    // Client IDs
    public static final String CLIENT_ID_GATEWAY = "fp_micro_gateway";
    public static final String CLIENT_ID_FRONTEND = "fp_frontend";

    // OAuth2 scopes
    public static final String SCOPE_GATEWAY_READ = "gateway.read";
    public static final String SCOPE_GATEWAY_WRITE = "gateway.write";
    public static final String SCOPE_OPENID = "openid";
    public static final String SCOPE_PROFILE = "profile";
    public static final String SCOPE_API_READ = "api.read";
    public static final String SCOPE_API_WRITE = "api.write";

    // Redirect URIs
    public static final String REDIRECT_PATH = "/callback";

    // Roles
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";

    // Admin user initial credentials
    public static final String ADMIN_USERNAME = "adminUser@adminProducts.com";
    public static final String ADMIN_PASSWORD = "admin123";

    // JWT claims
    public static final String CLAIM_ROLES = "roles";

    // Public endpoints
    public static final String[] PUBLIC_AUTH_REGISTRATION = {"/auth/api/register", "/user/register"};
    public static final String[] PUBLIC_OAUTH_ENDPOINTS = {"/oauth2/consent", "/oauth2/server-info", "/oauth2/test-direct"};
    public static final String[] PUBLIC_ERROR_ENDPOINTS = {"/error"};
    public static final String[] PUBLIC_LOGIN_ENDPOINTS = {"/login"};
    public static final String[] PUBLIC_STATIC_RESOURCES = {"/css/**", "/js/**", "/images/**"};
    
    // Admin endpoints (require authentication and ADMIN role)
    public static final String[] ADMIN_ENDPOINTS = {"/admin/**"};
}
