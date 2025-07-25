package com.aspiresys.fp_micro_authservice.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.aspiresys.fp_micro_authservice.user.AppUser;
import com.aspiresys.fp_micro_authservice.user.AppUserRepository;
import com.aspiresys.fp_micro_authservice.user.role.Role;
import com.aspiresys.fp_micro_authservice.user.role.RoleRepository;

import lombok.extern.java.Log;

import java.util.Set;

import static com.aspiresys.fp_micro_authservice.config.AuthConstants.*;

/**
 * DataInitializer is a Spring component that initializes essential data in the database
 * when the application starts. It implements {@link CommandLineRunner} to execute its logic
 * after the Spring Boot application context is loaded.
 * <p>
 * This class ensures that the default roles ("ROLE_USER" and "ROLE_ADMIN") exist in the system,
 * and creates an initial admin user with the "ROLE_ADMIN" role if it does not already exist.
 * <p>
 * The admin user's credentials are:
 * <ul>
 *   <li>Username: adminUser@adminProducts.com</li>
 *   <li>Password: admin123</li>
 * </ul>
 * <p>
 * Dependencies are injected via Spring's {@code @Autowired} annotation.
 * Logging is provided to indicate the creation of roles and the admin user.
 */
@Component
@Log
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;
    
    @Autowired
    private AppUserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        initializeRoles();
        initializeAdminUser();
    }

    
    private void initializeRoles() {
        
        if (roleRepository.findByName(ROLE_USER).isEmpty()) {
            Role userRole = new Role();
            userRole.setName(ROLE_USER);
            roleRepository.save(userRole);
            log.info("Role " + ROLE_USER + " created successfully");
        }

        
        if (roleRepository.findByName(ROLE_ADMIN).isEmpty()) {
            Role adminRole = new Role();
            adminRole.setName(ROLE_ADMIN);
            roleRepository.save(adminRole);
            log.info("Role " + ROLE_ADMIN + " created successfully");
        }
    }

    
    private void initializeAdminUser() {
        if (userRepository.findByUsername(ADMIN_USERNAME).isEmpty()) {
            Role adminRole = roleRepository.findByName(ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException(ROLE_ADMIN + " not found"));
            
            AppUser adminUser = AppUser.builder()
                    .username(ADMIN_USERNAME)
                    .password(passwordEncoder.encode(ADMIN_PASSWORD))
                    .roles(Set.of(adminRole))
                    .build();
            
            userRepository.save(adminUser);
            StringBuilder sb = new StringBuilder();
            sb.append("Admin user created successfully:\n")
              .append("  Username: ").append(ADMIN_USERNAME).append("\n")
              .append("  Password: ").append(ADMIN_PASSWORD).append("\n")
              .append("  Roles: ").append(ROLE_ADMIN);
            log.info(sb.toString());
        }
    }
}
