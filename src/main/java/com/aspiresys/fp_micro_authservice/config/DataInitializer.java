package com.aspiresys.fp_micro_authservice.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.aspiresys.fp_micro_authservice.user.AppUser;
import com.aspiresys.fp_micro_authservice.user.AppUserRepository;
import com.aspiresys.fp_micro_authservice.user.role.Role;
import com.aspiresys.fp_micro_authservice.user.role.RoleRepository;

import java.util.Set;

/**
 * Componente que inicializa datos básicos en la base de datos al arranque de la aplicación.
 * Crea roles por defecto y un usuario administrador si no existen.
 */
@Component
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

    /**
     * Inicializa los roles básicos del sistema si no existen.
     */
    private void initializeRoles() {
        // Crear rol USER si no existe
        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            Role userRole = new Role();
            userRole.setName("ROLE_USER");
            roleRepository.save(userRole);
            System.out.println("Rol ROLE_USER creado exitosamente");
        }

        // Crear rol ADMIN si no existe
        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            Role adminRole = new Role();
            adminRole.setName("ROLE_ADMIN");
            roleRepository.save(adminRole);
            System.out.println("Rol ROLE_ADMIN creado exitosamente");
        }
    }

    /**
     * Crea un usuario administrador por defecto si no existe.
     */
    private void initializeAdminUser() {
        if (userRepository.findByUsername("adminUser@adminProducts.com").isEmpty()) {
            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new RuntimeException("ROLE_ADMIN no encontrado"));
            
            AppUser adminUser = AppUser.builder()
                    .username("adminUser@adminProducts.com")
                    .password(passwordEncoder.encode("admin123"))
                    .roles(Set.of(adminRole))
                    .build();
            
            userRepository.save(adminUser);
            System.out.println("Usuario administrador creado exitosamente:");
            System.out.println("  Username: adminUser@adminProducts.com");
            System.out.println("  Password: admin123");
            System.out.println("  Roles: ROLE_ADMIN");
        }
    }
}
