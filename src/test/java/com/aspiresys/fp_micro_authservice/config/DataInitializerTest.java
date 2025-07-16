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
        // Role configuration for tests
        userRole = new Role();
        userRole.setName(ROLE_USER);

        adminRole = new Role();
        adminRole.setName(ROLE_ADMIN);
    }

    @Test
    void shouldCreateRolesWhenTheyDoNotExist() throws Exception {
        // Configure role behavior
        when(roleRepository.findByName(ROLE_USER)).thenReturn(Optional.empty())
                                                 .thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ROLE_ADMIN)).thenReturn(Optional.empty())
                                                 .thenReturn(Optional.of(adminRole));
        when(roleRepository.save(any(Role.class))).thenReturn(userRole).thenReturn(adminRole);

        // Configure behavior for admin user
        when(userRepository.findByUsername(ADMIN_USERNAME)).thenReturn(Optional.empty());
        when(passwordEncoder.encode(ADMIN_PASSWORD)).thenReturn("encodedPassword");

        // Execute initialization
        dataInitializer.run();

        // Verify that both roles were saved
        verify(roleRepository).save(argThat(role -> role.getName().equals(ROLE_USER)));
        verify(roleRepository).save(argThat(role -> role.getName().equals(ROLE_ADMIN)));

        // Verify that admin user was saved
        verify(userRepository).save(any(AppUser.class));
    }

    @Test
    void shouldNotCreateRolesWhenTheyAlreadyExist() throws Exception {
        // Configure that roles already exist
        when(roleRepository.findByName(ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ROLE_ADMIN)).thenReturn(Optional.of(adminRole));

        // Execute initialization
        dataInitializer.run();

        // Verify that no roles were attempted to be saved
        verify(roleRepository, never()).save(any(Role.class));
    }

    @Test
    void shouldCreateAdminUserWhenItDoesNotExist() throws Exception {
        // Configure behavior for roles
        when(roleRepository.findByName(ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ROLE_ADMIN)).thenReturn(Optional.of(adminRole));

        // Configure behavior for admin user
        when(userRepository.findByUsername(ADMIN_USERNAME)).thenReturn(Optional.empty());
        when(passwordEncoder.encode(ADMIN_PASSWORD)).thenReturn("encodedPassword");

        // Execute initialization
        dataInitializer.run();

        // Verify that admin user was saved with correct data
        verify(userRepository).save(argThat(user ->
            user.getUsername().equals(ADMIN_USERNAME) &&
            user.getRoles().stream().anyMatch(role -> role.getName().equals(ROLE_ADMIN))
        ));
    }

    @Test
    void shouldNotCreateAdminUserWhenItAlreadyExists() throws Exception {
        // Create existing admin user
        AppUser existingAdmin = AppUser.builder()
                .username(ADMIN_USERNAME)
                .password("existingEncodedPassword")
                .roles(Set.of(adminRole))
                .build();

        // Configure behavior for repository
        when(userRepository.findByUsername(ADMIN_USERNAME)).thenReturn(Optional.of(existingAdmin));

        // Execute initialization
        dataInitializer.run();

        // Verify that no users were attempted to be saved
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void shouldThrowExceptionWhenAdminRoleNotFoundForAdminUser() {
        // Configure that both roles exist
        when(roleRepository.findByName(ROLE_USER)).thenReturn(Optional.of(userRole));
        when(roleRepository.findByName(ROLE_ADMIN)).thenReturn(Optional.empty());
        when(userRepository.findByUsername(ADMIN_USERNAME)).thenReturn(Optional.empty());

        // Verify that the expected exception is thrown
        Exception exception = assertThrows(RuntimeException.class, () -> {
            dataInitializer.run();
        });

        assertTrue(exception.getMessage().contains("not found"));
        verify(userRepository, never()).save(any(AppUser.class));
    }
}