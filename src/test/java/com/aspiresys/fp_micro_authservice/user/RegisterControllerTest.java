package com.aspiresys.fp_micro_authservice.user;

import com.aspiresys.fp_micro_authservice.user.role.Role;
import com.aspiresys.fp_micro_authservice.user.role.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RegisterController
 * This class tests the user registration functionality, ensuring that it behaves correctly under various conditions.
 */
@ExtendWith(MockitoExtension.class)
class RegisterControllerTest {

    @Mock
    private AppUserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private RegisterController registerController;

    private AppUser testUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        testUser = new AppUser();
        testUser.setUsername("test@example.com");
        testUser.setPassword("password123");

        userRole = new Role();
        userRole.setName("ROLE_USER");
    }

    @Test
    void shouldRegisterNewUserSuccessfully() {
        // Mocking behavior
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(testUser.getPassword())).thenReturn("encodedPassword");
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole));
        when(userRepository.save(any(AppUser.class))).thenReturn(testUser);

        // Execute registration
        ResponseEntity<String> response = registerController.registerUser(testUser);

        // Verify
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("User registered successfully", response.getBody());
        verify(userRepository).save(any(AppUser.class));
    }

    @Test
    void shouldReturnConflictWhenUserAlreadyExists() {
        // Mocking behavior
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.of(testUser));

        // Execute registration
        ResponseEntity<String> response = registerController.registerUser(testUser);

        // Verify
        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertEquals("User already exists", response.getBody());
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void shouldReturnErrorWhenDefaultRoleNotFound() {
        // Mocking behavior
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.empty());
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.empty());

        // Execute registration
        ResponseEntity<String> response = registerController.registerUser(testUser);

        // Verify
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertTrue(response.getBody().contains("Default role not found"));
        verify(userRepository, never()).save(any(AppUser.class));
    }

    @Test
    void shouldHandleExceptionsGracefully() {
        // Mocking behavior
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.empty());
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole));
        when(userRepository.save(any(AppUser.class))).thenThrow(new RuntimeException("Database error"));

        // Execute registration
        ResponseEntity<String> response = registerController.registerUser(testUser);

        // Verify
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertTrue(response.getBody().contains("Error registering user"));
    }

    @Test
    void shouldEncodePasswordBeforeSaving() {
        // Mocking behavior
        when(userRepository.findByUsername(testUser.getUsername())).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole));
        when(userRepository.save(any(AppUser.class))).thenReturn(testUser);

        // Execute registration
        registerController.registerUser(testUser);

        // Verify that the password encoder was called
        verify(passwordEncoder).encode("password123");

        // Verify that the user was saved with the encoded password
        verify(userRepository).save(argThat(user ->
            user.getPassword().equals("encodedPassword")
        ));
    }
}
