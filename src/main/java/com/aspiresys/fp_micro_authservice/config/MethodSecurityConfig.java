package com.aspiresys.fp_micro_authservice.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Configuration class for enabling method-level security.
 * <p>
 * This configuration enables the use of security annotations such as:
 * <ul>
 *   <li>{@code @PreAuthorize} - for pre-invocation authorization</li>
 *   <li>{@code @PostAuthorize} - for post-invocation authorization</li>
 *   <li>{@code @Secured} - for role-based security</li>
 * </ul>
 * </p>
 * 
 * <p>
 * The {@code prePostEnabled = true} parameter enables the use of 
 * {@code @PreAuthorize} and {@code @PostAuthorize} annotations.
 * </p>
 * 
 * @author Bruno Gil
 * @version 1.0
 * @since 1.0
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfig {
    // This class enables method-level security annotations
    // No additional configuration needed - the annotation does the work
}
