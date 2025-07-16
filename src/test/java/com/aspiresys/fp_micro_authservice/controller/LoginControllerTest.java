package com.aspiresys.fp_micro_authservice.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Unit tests for LoginController 
 * This class tests the login functionality of the application, ensuring that it behaves correctly under various conditions.
 */
@ExtendWith(MockitoExtension.class)
class LoginControllerTest {

    @InjectMocks
    private LoginController loginController;

    @Mock
    private Model model;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void shouldShowLoginPageWhenNotAuthenticated() {
        // Unauthenticated user setup
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        // Execute
        String viewName = loginController.login(null, null, model);

        // Verify
        assertEquals("login", viewName);
        verify(model, never()).addAttribute(eq("error"), any());
        verify(model, never()).addAttribute(eq("message"), any());
    }

    @Test
    void shouldRedirectToHomeWhenAlreadyAuthenticated() {
        // Authenticated user setup
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("user@example.com");

        // Execute
        String viewName = loginController.login(null, null, model);

        // Verify
        assertEquals("redirect:/", viewName);
        verify(model, never()).addAttribute(any(), any());
    }

    @Test
    void shouldShowErrorMessageOnFailedLogin() {
        // Unauthenticated user setup with error
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        // Execute
        String viewName = loginController.login("true", null, model);

        // Verificar
        assertEquals("login", viewName);
        verify(model).addAttribute("error", "Incorrect username or password");
    }

    @Test
    void shouldShowLogoutMessageAfterLogout() {
        // Unauthenticated user setup after logout
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        // Execute
        String viewName = loginController.login(null, "true", model);

        // Verify
        assertEquals("login", viewName);
        verify(model).addAttribute("message", "You have logged out successfully");
    }

    @Test
    void shouldHandleExceptionsGracefully() {
        // Configure that an exception is thrown
        when(securityContext.getAuthentication()).thenThrow(new RuntimeException("Security context error"));

        // Execute
        String viewName = loginController.login(null, null, model);

        // Verify
        assertEquals("login", viewName);
        verify(model).addAttribute(eq("error"), contains("An error occurred during login"));
    }

    @Test
    void shouldReturnHomeView() {

        String viewName = loginController.home();
        assertEquals("welcome", viewName);
    }

    @Test
    void shouldNotShowErrorOrLogoutMessageWhenNoParameters() {
        // Unauthenticated user setup
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);
        String viewName = loginController.login(null, null, model);
        assertEquals("login", viewName);
        verify(model, never()).addAttribute(any(), any());
    }

    @Test
    void shouldHandleAnonymousUser() {
        // Unauthenticated user setup
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("anonymousUser");
        String viewName = loginController.login(null, null, model);
        assertEquals("login", viewName);
        verify(model, never()).addAttribute(any(), any());
    }
}
