package com.aspiresys.fp_micro_authservice.config;

import com.aspiresys.fp_micro_authservice.user.AppUser;
import com.aspiresys.fp_micro_authservice.user.AppUserRepository;
import com.aspiresys.fp_micro_authservice.user.role.Role;
import com.aspiresys.fp_micro_authservice.user.role.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;

import static com.aspiresys.fp_micro_authservice.config.AuthConstants.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class DataInitializerTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private AppUserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private DataInitializer dataInitializer;

    private Role userRole;
    private Role adminRole;

    @BeforeEach
    void setUp() {
        // Configurar roles para las pruebas
        userRole = new Role();
        userRole.setName(ROLE_USER);

        adminRole = new Role();
        adminRole.setName(ROLE_ADMIN);
    }

    @Test
    void shouldCreateRolesWhenTheyDoNotExist() throws Exception {
        // Configurar comportamiento del repositorio para roles
        when(roleRepository.findByName(ROLE_USER)).thenReturn(Optional.empty())
                                                 .thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ROLE_ADMIN)).thenReturn(Optional.empty())
                                                 .thenReturn(Optional.of(adminRole));
        when(roleRepository.save(any(Role.class))).thenReturn(userRole).thenReturn(adminRole);

        // Configurar comportamiento para el usuario admin
        when(userRepository.findByUsername(ADMIN_USERNAME)).thenReturn(Optional.empty());
        when(passwordEncoder.encode(ADMIN_PASSWORD)).thenReturn("encodedPassword");

        // Ejecutar la inicialización
        dataInitializer.run();

        // Verificar que se guardaron ambos roles
        verify(roleRepository).save(argThat(role -> role.getName().equals(ROLE_USER)));
        verify(roleRepository).save(argThat(role -> role.getName().equals(ROLE_ADMIN)));
        
        // Verificar que se guardó el usuario admin
        verify(userRepository).save(any(AppUser.class));
    }

    @Test
    void shouldNotCreateRolesWhenTheyAlreadyExist() throws Exception {
        // Configurar que los roles ya existen
        when(roleRepository.findByName(ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ROLE_ADMIN)).thenReturn(Optional.of(adminRole));

        // Ejecutar la inicialización
        dataInitializer.run();

        // Verificar que no se intentó guardar ningún rol
        verify(roleRepository, never()).save(any(Role.class));
    }

    @Test
    void shouldCreateAdminUserWhenItDoesNotExist() throws Exception {
        // Configurar comportamiento para roles
        when(roleRepository.findByName(ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ROLE_ADMIN)).thenReturn(Optional.of(adminRole));
        
        // Configurar comportamiento para usuario admin
        when(userRepository.findByUsername(ADMIN_USERNAME)).thenReturn(Optional.empty());
        when(passwordEncoder.encode(ADMIN_PASSWORD)).thenReturn("encodedPassword");

        // Ejecutar la inicialización
        dataInitializer.run();

        // Verificar que se guardó el usuario admin con los datos correctos
        verify(userRepository).save(argThat(user -> 
            user.getUsername().equals(ADMIN_USERNAME) &&
            user.getRoles().stream().anyMatch(role -> role.getName().equals(ROLE_ADMIN))
        ));
    }

    @Test
    void shouldNotCreateAdminUserWhenItAlreadyExists() throws Exception {
        // Crear usuario admin existente
        AppUser existingAdmin = AppUser.builder()
                .username(ADMIN_USERNAME)
                .password("existingEncodedPassword")
                .roles(Set.of(adminRole))
                .build();

        // Configurar comportamiento del repositorio
        when(userRepository.findByUsername(ADMIN_USERNAME)).thenReturn(Optional.of(existingAdmin));

        // Ejecutar la inicialización
        dataInitializer.run();

        // Verificar que no se intentó guardar ningún usuario
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void shouldThrowExceptionWhenAdminRoleNotFoundForAdminUser() {
        // Configurar que ambos roles existen
        when(roleRepository.findByName(ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ROLE_ADMIN)).thenReturn(Optional.empty());
        when(userRepository.findByUsername(ADMIN_USERNAME)).thenReturn(Optional.empty());

        // Verificar que se lanza la excepción esperada
        Exception exception = assertThrows(RuntimeException.class, () -> {
            dataInitializer.run();
        });
        
        assertTrue(exception.getMessage().contains("no encontrado"));
        verify(userRepository, never()).save(any(AppUser.class));
    }
}