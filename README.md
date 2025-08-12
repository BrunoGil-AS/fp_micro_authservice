# Ecommerce Micro Auth Service

## Overview

The **Ecommerce Micro Auth Service** is a Spring Boot OAuth2 Authorization Server that provides centralized authentication and authorization for the Ecommerce (Final Project) microservices ecosystem. It implements the OAuth2 and OpenID Connect protocols, serving as the identity provider for all other services in the system.

This service handles user authentication, authorization code generation, JWT token issuance, and user management. It acts as the security hub that enables secure communication between the gateway, microservices, and frontend applications.

## Architecture

![Service Structure](<diagrams/Final Project - AuthFlow.png>)

```text
┌─────────────────┐
│   Frontend      │
│  (React/Vue)    │
│ :3000           │
└─────────┬───────┘
          │ OAuth2 Flow
          │
┌─────────▼───────┐    ┌─────────────────┐
│   API Gateway   │◄───│ Other Services  │
│   :8080         │    │ (User, Product, │
└─────────┬───────┘    │ Order)          │
          │            └─────────────────┘
          │ JWT Validation
          │
┌─────────▼───────┐
│  Auth Service   │
│    :8081        │
│                 │
├─ OAuth2 Server  │
├─ User Management│
├─ JWT Generation │
├─ Role Management│
└─────────┬───────┘
          │
┌─────────▼───────┐
│   MySQL DB      │
│   :3306         │
│  (auth_db)      │
└─────────────────┘
```

## Key Features

- **OAuth2 Authorization Server**: Complete OAuth2 and OpenID Connect implementation
- **JWT Token Generation**: RSA-signed JWT tokens with custom claims
- **User Management**: User registration, authentication, and role-based access control
- **Role-Based Authorization**: USER and ADMIN role support
- **PKCE Support**: Enhanced security for public clients (frontend applications)
- **Multi-Client Support**: Different OAuth2 clients for gateway and frontend
- **Database Integration**: MySQL database for persistent user and role storage
- **Thymeleaf Templates**: Web-based login and consent pages
- **Comprehensive Logging**: Structured logging for authentication, OAuth2, and database operations

## Technology Stack

- **Spring Boot**: 3.5.0
- **Spring Security**: OAuth2 Authorization Server
- **Spring Cloud Config**: Centralized configuration management
- **Spring Data JPA**: Database operations
- **MySQL**: Primary database
- **Thymeleaf**: Template engine for web pages
- **Project Lombok**: Code generation
- **HikariCP**: Connection pooling
- **Java**: 17
- **Maven**: Build tool

## Configuration

### Core Application Properties

The main configuration is located in [`application.properties`](src/main/resources/application.properties):

```properties
spring.application.name=fp_micro_authservice
```

[`Dev`](src/main/resources/application-dev.properties) profile includes more configurations as connection to config server and environment variables

```properties
# Config client configuration
spring.config.import=optional:configserver:http://localhost:8888

# Environment configuration
service.env.frontend.server=http://localhost:3000
service.env.auth.client.secret={noop}12345

# Debug logging for security and web
logging.level.org.springframework.web=DEBUG
logging.level.org.springframework.security=DEBUG
```

### External Configuration

The external configuration is managed via Config Server in [`fp_micro_authservice.properties`](../fp_files_configproperties/authservice/fp_micro_authservice-dev.properties):

```properties
# Server Configuration
# environment configuration for development
service.env.frontend.server=http://localhost:3000
service.env.auth.client.secret={noop}12345

#i want to see logs from web request and security
logging.level.org.springframework.web=DEBUG
logging.level.org.springframework.security=DEBUG

# Configuración de base de datos del auth-service
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db?allowPublicKeyRetrieval=true&useSSL=false
spring.datasource.username=service_auth
spring.datasource.password=securePassword123
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQLDialect


# Seguridad OAuth2 (Spring Authorization Server)
spring.security.oauth2.authorizationserver.issuer-url=http://localhost:8081
```

### Important Configuration Settings

#### 1. Database Configuration

```properties
# MySQL Database Connection
spring.datasource.url=jdbc:mysql://localhost:3306/auth_db?allowPublicKeyRetrieval=true&useSSL=false
spring.datasource.username=service_auth
spring.datasource.password=securePassword123

# JPA Settings
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
```

#### 2. OAuth2 Configuration

```properties
# Authorization Server Issuer URL
spring.security.oauth2.authorizationserver.issuer-url=http://localhost:8081

# Frontend and Client Configuration
service.env.frontend.server=http://localhost:3000
service.env.auth.client.secret={noop}12345
```

## Key Components

### 1. Main Application Class

**File**: [`FpMicroAuthserviceApplication.java`](src/main/java/com/aspiresys/fp_micro_authservice/FpMicroAuthserviceApplication.java)

```java
@SpringBootApplication
@Log
public class FpMicroAuthserviceApplication {
    public static void main(String[] args) {
        SpringApplication.run(FpMicroAuthserviceApplication.class, args);
    }

    @Component
    public class DataSeeder implements CommandLineRunner {
        @Override
        public void run(String... args) {
            // Creates default USER role and test user
            Role role = roleRepo.findByName("ROLE_USER")
                .orElseGet(() -> roleRepo.save(new Role(null, "ROLE_USER")));

            AppUser user = userRepo.findByUsernameWithRoles("testUser@example.com")
                .orElse(null);
            if (user == null) {
                user = AppUser.builder()
                    .username("testUser@example.com")
                    .password(encoder.encode("1234"))
                    .roles(Set.of(role))
                    .build();
                userRepo.save(user);
            }
        }
    }
}
```

The `DataSeeder` component initializes default roles and a test user on application startup. It checks if the `ROLE_USER` exists and creates it if not. It also creates a test user with the username `testUser@example.com` and password `1234`.

### 2. Security Configuration

**File**: [`SecurityConfig.java`](src/main/java/com/aspiresys/fp_micro_authservice/config/SecurityConfig.java)

This class implements dual security filter chains:

#### OAuth2 Authorization Server Filter Chain

```java
@Bean
@Order(1)
public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
        new OAuth2AuthorizationServerConfigurer();

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
        );

    return http.build();
}
```

#### Default Application Security Filter Chain

```java
@Bean
@Order(2)
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/auth/api/register", "/user/register").permitAll()
            .requestMatchers("/oauth2/consent", "/oauth2/server-info").permitAll()
            .requestMatchers("/error").permitAll()
            .requestMatchers("/login").permitAll()
            .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()
            .anyRequest().authenticated())
        .formLogin(form -> form
            .loginPage("/login")
            .defaultSuccessUrl("/", false)
            .failureUrl("/login?error=true")
            .permitAll())
        .logout(logout -> logout
            .logoutSuccessUrl("/login?logout=true")
            .invalidateHttpSession(true)
            .deleteCookies("JSESSIONID")
            .permitAll());

    return http.build();
}
```

This `Bean` called `defaultSecurityFilterChain` configures the default security filter chain for the application:

- **CSRF Protection**: Enabled with a cookie-based CSRF token repository.
- **CORS Configuration**: Allows cross-origin requests.
- **Authorization Rules**: Defines public endpoints for registration, consent, and static resources, while securing all other endpoints.
- **Form Login**: Custom login page with success and failure URLs.
- **Logout**: Configures logout behavior, including invalidating the session and deleting cookies.

#### JWT Configuration

```java
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
```

This configuration generates RSA keys for signing JWT tokens and customizes the JWT claims to include user roles:

- **jwkSource**: This bean generates RSA keys and creates a JWK set for JWT signing.
- **jwtCustomizer**: This bean customizes the JWT claims to include user roles, which are extracted from the authenticated principal's authorities.

### 3. OAuth2 Client Configuration

**File**: [`ClientConfig.java`](src/main/java/com/aspiresys/fp_micro_authservice/config/ClientConfig.java)

Defines two OAuth2 clients:

#### API Gateway Client (Machine-to-Machine)

```java
@Bean
RegisteredClient gatewayClient = RegisteredClient.withId(UUID.randomUUID().toString())
    .clientId("fp_micro_gateway")
    .clientSecret(authClientSecret)
    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
    .scope("gateway.read")
    .scope("gateway.write")
    .build();
```

This bean defines the API Gateway client with the necessary credentials and scopes.

#### Frontend Client (Public with PKCE)

```java
RegisteredClient reactClient = RegisteredClient.withId(UUID.randomUUID().toString())
    .clientId("fp_frontend")
    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public client
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
    .redirectUri(frontendUrl + "/callback")
    .postLogoutRedirectUri(frontendUrl)
    .scope("openid")
    .scope("profile")
    .scope("api.read")
    .scope("api.write")
    .clientSettings(ClientSettings.builder()
        .requireAuthorizationConsent(false)
        .requireProofKey(true) // PKCE required
        .build())
    .tokenSettings(TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofMinutes(15))
        .refreshTokenTimeToLive(Duration.ofDays(30))
        .reuseRefreshTokens(false)
        .build())
    .build();
```

This bean defines the frontend client with PKCE support, allowing secure authorization code flow.

- **PKCE**: Proof Key for Code Exchange is enabled for enhanced security.

### 4. Data Initialization

**File**: [`DataInitializer.java`](src/main/java/com/aspiresys/fp_micro_authservice/config/DataInitializer.java)

Automatically creates default roles and admin user:

```java
@Component
@Log
public class DataInitializer implements CommandLineRunner {

    @Override
    public void run(String... args) throws Exception {
        initializeRoles();
        initializeAdminUser();
    }

    private void initializeRoles() {
        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            Role userRole = new Role();
            userRole.setName("ROLE_USER");
            roleRepository.save(userRole);
            log.info("Role ROLE_USER created successfully");
        }

        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            Role adminRole = new Role();
            adminRole.setName("ROLE_ADMIN");
            roleRepository.save(adminRole);
            log.info("Role ROLE_ADMIN created successfully");
        }
    }

    private void initializeAdminUser() {
        if (userRepository.findByUsername("adminUser@adminProducts.com").isEmpty()) {
            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseThrow(() -> new RuntimeException("ROLE_ADMIN not found"));

            AppUser adminUser = AppUser.builder()
                .username("adminUser@adminProducts.com")
                .password(passwordEncoder.encode("admin123"))
                .roles(Set.of(adminRole))
                .build();

            userRepository.save(adminUser);
            log.info("Admin user created successfully: adminUser@adminProducts.com");
        }
    }
}
```

This class initializes the database with default roles and an admin user on application startup. It checks if the `ROLE_USER` and `ROLE_ADMIN` exist and creates them if not. It also creates an admin user with the username `adminUser@adminProducts.com`.

### 5. User Entity and Repository

**File**: [`AppUser.java`](src/main/java/com/aspiresys/fp_micro_authservice/user/AppUser.java)

```java
@Entity
@Table(name = "app_user", uniqueConstraints = @UniqueConstraint(columnNames = "username"))
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder @ToString
public class AppUser {
    @Id @GeneratedValue
    private Long id;

    private String username;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    @Builder.Default
    private Set<Role> roles = new HashSet<>();
}
```

This entity represents a user in the system, with fields for username, password, and roles. It uses JPA annotations for persistence and Lombok annotations for boilerplate code reduction.

### 6. Constants Definition

**File**: [`AuthConstants.java`](src/main/java/com/aspiresys/fp_micro_authservice/config/AuthConstants.java)

```java
public final class AuthConstants {
    // Client IDs
    public static final String CLIENT_ID_GATEWAY = "fp_micro_gateway";
    public static final String CLIENT_ID_FRONTEND = "fp_frontend";

    // OAuth2 Scopes
    public static final String SCOPE_GATEWAY_READ = "gateway.read";
    public static final String SCOPE_GATEWAY_WRITE = "gateway.write";
    public static final String SCOPE_OPENID = "openid";
    public static final String SCOPE_PROFILE = "profile";
    public static final String SCOPE_API_READ = "api.read";
    public static final String SCOPE_API_WRITE = "api.write";

    // Roles
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";

    // Admin credentials
    public static final String ADMIN_USERNAME = "adminUser@adminProducts.com";
    public static final String ADMIN_PASSWORD = "admin123";

    // Public endpoints
    public static final String[] PUBLIC_AUTH_REGISTRATION = {"/auth/api/register", "/user/register"};
    public static final String[] PUBLIC_OAUTH_ENDPOINTS = {"/oauth2/consent", "/oauth2/server-info", "/oauth2/test-direct"};
    public static final String[] PUBLIC_ERROR_ENDPOINTS = {"/error"};
    public static final String[] PUBLIC_LOGIN_ENDPOINTS = {"/login"};
    public static final String[] PUBLIC_STATIC_RESOURCES = {"/css/**", "/js/**", "/images/**"};
}
```

This class defines constants used throughout the application, including client IDs, OAuth2 scopes, roles, admin credentials, and public endpoints.

## API Endpoints

### OAuth2 Endpoints

| Method | Endpoint                            | Description                   |
| ------ | ----------------------------------- | ----------------------------- |
| GET    | `/oauth2/authorize`                 | OAuth2 authorization endpoint |
| POST   | `/oauth2/token`                     | Token exchange endpoint       |
| GET    | `/oauth2/jwks`                      | JSON Web Key Set endpoint     |
| GET    | `/.well-known/openid-configuration` | OpenID Connect discovery      |
| GET    | `/oauth2/consent`                   | User consent page             |
| GET    | `/oauth2/server-info`               | Server configuration info     |
| GET    | `/oauth2/test-direct`               | Test endpoint reachability    |

### Authentication Endpoints

| Method | Endpoint             | Description                     |
| ------ | -------------------- | ------------------------------- |
| GET    | `/login`             | Login page                      |
| POST   | `/login`             | Process login                   |
| POST   | `/logout`            | Logout                          |
| POST   | `/auth/api/register` | User registration API           |
| POST   | `/user/register`     | User registration (alternative) |

### User Management Endpoints

| Method | Endpoint        | Access Level  | Description           |
| ------ | --------------- | ------------- | --------------------- |
| GET    | `/`             | Authenticated | User dashboard        |
| GET    | `/user/profile` | USER          | User profile page     |
| GET    | `/admin/users`  | ADMIN         | Admin user management |

## OAuth2 Flow Examples

### 1. Authorization Code Flow (Frontend)

#### Step 1: Get Authorization Code

```bash
GET /oauth2/authorize?response_type=code&client_id=fp_frontend&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20api.read%20api.write&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

#### Step 2: Exchange Code for Token

```bash
curl -X POST "http://localhost:8081/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=fp_frontend" \
  -d "code_verifier=CODE_VERIFIER"
```

### 2. Client Credentials Flow (Gateway)

```bash
curl -X POST "http://localhost:8081/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'fp_micro_gateway:12345' | base64)" \
  -d "grant_type=client_credentials" \
  -d "scope=gateway.read gateway.write"
```

### 3. Refresh Token Flow

```bash
curl -X POST "http://localhost:8081/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=REFRESH_TOKEN" \
  -d "client_id=fp_frontend"
```

## Database Schema

### Tables Structure

```sql
-- Users table
CREATE TABLE app_user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

-- Roles table
CREATE TABLE role (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);

-- User-Role mapping table
CREATE TABLE user_roles (
    user_id BIGINT,
    role_id BIGINT,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES app_user(id),
    FOREIGN KEY (role_id) REFERENCES role(id)
);
```

### Default Data

The system automatically creates:

- **Roles**: `ROLE_USER`, `ROLE_ADMIN`
- **Admin User**:
  - Username: `adminUser@adminProducts.com`
  - Password: `admin123`
  - Role: `ROLE_ADMIN`
- **Test User**:
  - Username: `testUser@example.com`
  - Password: `1234`
  - Role: `ROLE_USER`

## Running the Application

### Prerequisites

- Java 17 or higher
- Maven 3.6+
- MySQL 8.0+
- Running Config Server (`fp_micro_configserver` on port 8888)

### Development Setup

#### 1. Database Setup

```sql
-- Create database
CREATE DATABASE auth_db;

-- Create user
CREATE USER 'service_auth'@'localhost' IDENTIFIED BY 'securePassword123';
GRANT ALL PRIVILEGES ON auth_db.* TO 'service_auth'@'localhost';
FLUSH PRIVILEGES;
```

#### 2. Start the Application

```bash
# Clone the repository
git clone <repository-url>
cd fp_micro_authservice

# Start the auth service
./mvnw spring-boot:run

# Or run the JAR file
./mvnw clean package
java -jar target/fp_micro_authservice-0.0.1-SNAPSHOT.war
```

### Startup Sequence

1. **Config Server** (port 8888)
2. **MySQL Database** (port 3306)
3. **Auth Service** (port 8081)
4. **Other microservices** (ports 8080+)

### Verification

Once started, verify the auth service is working:

```bash
# Check server info
curl http://localhost:8081/oauth2/server-info

# Check health endpoint
curl http://localhost:8081/actuator/health

# Test login page
curl http://localhost:8081/login

# Check OpenID Connect discovery
curl http://localhost:8081/.well-known/openid-configuration
```

## User Management

### User Registration

Users can register through the API endpoint:

```bash
curl -X POST "http://localhost:8081/auth/api/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser@example.com",
    "password": "userpassword"
  }'
```

### Default Users for Testing

The system provides default users for immediate testing:

1. **Admin User**:

   - Username: `adminUser@adminProducts.com`
   - Password: `admin123`
   - Role: `ROLE_ADMIN`

2. **Test User**:
   - Username: `testUser@example.com`
   - Password: `1234`
   - Role: `ROLE_USER`

## Monitoring and Troubleshooting

### Log Configuration

The service uses comprehensive Logback configuration with specialized log files:

#### Log File Structure

```text
logs/auth-service/
├── auth-service.log           # General auth service logs
├── auth-authentication.log    # Authentication-specific logs
├── auth-oauth2.log           # OAuth2 and JWT logs
├── auth-database.log         # Database and JPA logs
├── auth-service-error.log    # Error logs (WARN and above)
└── archived/                 # Compressed archived logs
```

#### Logging Configuration by Component

**Auth Service Application**:

```xml
<logger name="com.aspiresys.fp_micro_authservice" level="DEBUG">
    <appender-ref ref="FILE_AUTH"/>
    <appender-ref ref="FILE_ERROR"/>
    <appender-ref ref="CONSOLE"/> <!-- Development only -->
</logger>
```

**Spring Security**:

```xml
<logger name="org.springframework.security" level="INFO">
    <appender-ref ref="FILE_AUTHENTICATION"/>
    <appender-ref ref="FILE_ERROR"/>
</logger>
```

**OAuth2 Authorization Server**:

```xml
<logger name="org.springframework.security.oauth2.server.authorization" level="DEBUG">
    <appender-ref ref="FILE_OAUTH2"/>
    <appender-ref ref="FILE_ERROR"/>
</logger>
```

**Database Operations**:

```xml
<logger name="org.hibernate" level="INFO">
    <appender-ref ref="FILE_DATABASE"/>
    <appender-ref ref="FILE_ERROR"/>
</logger>

<logger name="org.hibernate.SQL" level="DEBUG">
    <appender-ref ref="FILE_DATABASE"/>
</logger>
```

#### Log Rotation Configuration

- **Auth Service Logs**: 40MB max file size, 30 days retention, 600MB total cap
- **Authentication Logs**: 30MB max file size, 45 days retention, 500MB total cap
- **OAuth2 Logs**: 25MB max file size, 45 days retention, 400MB total cap
- **Database Logs**: 20MB max file size, 30 days retention, 300MB total cap
- **Error Logs**: 25MB max file size, 60 days retention, 500MB total cap

### Health Monitoring

```bash
# Application health
curl http://localhost:8081/actuator/health

# Database health
curl http://localhost:8081/actuator/health/db

# OAuth2 server configuration
curl http://localhost:8081/oauth2/server-info
```

### Common Issues and Solutions

#### 1. Database Connection Issues

```bash
# Check database connectivity
mysql -h localhost -u service_auth -p auth_db

# Verify connection pool settings
curl http://localhost:8081/actuator/metrics/hikaricp.connections.active
```

#### 2. OAuth2 Configuration Problems

```bash
# Check registered clients
curl http://localhost:8081/oauth2/server-info

# Verify JWK set
curl http://localhost:8081/oauth2/jwks

# Test authorization endpoint
curl "http://localhost:8081/oauth2/authorize?response_type=code&client_id=fp_frontend&redirect_uri=http://localhost:3000/callback&scope=openid"
```

#### 3. JWT Token Issues

```bash
# Check token endpoint
curl -X POST "http://localhost:8081/oauth2/token" \
  -H "Authorization: Basic $(echo -n 'fp_micro_gateway:12345' | base64)" \
  -d "grant_type=client_credentials&scope=gateway.read"

# Verify JWT structure
# Use jwt.io to decode and verify tokens
```

### Testing

Run the test suite:

```bash
./mvnw test
```

Key test classes:

- `DataInitializerTest`: Tests role and user initialization
- `RegisterControllerTest`: Tests user registration functionality
- `LoginControllerTest`: Tests authentication mechanisms

## Integration with Other Services

### Gateway Integration

The gateway validates JWT tokens using this service:

```properties
# In gateway configuration
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8081
```

### Service Discovery

The auth service can be registered with Eureka:

```properties
# Optional Eureka registration
eureka.client.service-url.defaultZone=http://localhost:8761/eureka/
spring.application.name=auth-service
```

## Best Practices

### Security

1. **Password Encoding**: Always use BCrypt for password hashing
2. **JWT Security**: Use RSA keys for JWT signing in production
3. **HTTPS**: Enable HTTPS for production environments
4. **Client Secrets**: Use strong, randomly generated client secrets
5. **Token Expiration**: Set appropriate token lifetimes

### Performance

1. **Connection Pooling**: Configure HikariCP appropriately
2. **Database Indexing**: Create indexes on frequently queried columns
3. **Token Storage**: Consider Redis for token storage in production
4. **Caching**: Implement caching for frequently accessed data

### Monitoring

1. **Health Checks**: Monitor application and database health
2. **Metrics**: Track authentication success/failure rates
3. **Logging**: Implement comprehensive audit logging
4. **Alerting**: Set up alerts for authentication failures and errors

## Contributing

1. Follow the existing code structure and naming conventions
2. Add tests for new functionality
3. Update documentation for configuration changes
4. Ensure security best practices are maintained
5. Test OAuth2 flows thoroughly
