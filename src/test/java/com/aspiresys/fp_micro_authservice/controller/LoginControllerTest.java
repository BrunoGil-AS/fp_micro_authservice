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
        // Configurar usuario no autenticado
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        // Ejecutar
        String viewName = loginController.login(null, null, model);

        // Verificar
        assertEquals("login", viewName);
        verify(model, never()).addAttribute(eq("error"), any());
        verify(model, never()).addAttribute(eq("message"), any());
    }

    @Test
    void shouldRedirectToHomeWhenAlreadyAuthenticated() {
        // Configurar usuario autenticado
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("user@example.com");

        // Ejecutar
        String viewName = loginController.login(null, null, model);

        // Verificar
        assertEquals("redirect:/", viewName);
        verify(model, never()).addAttribute(any(), any());
    }

    @Test
    void shouldShowErrorMessageOnFailedLogin() {
        // Configurar usuario no autenticado con error
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        // Ejecutar
        String viewName = loginController.login("true", null, model);

        // Verificar
        assertEquals("login", viewName);
        verify(model).addAttribute("error", "Incorrect username or password");
    }

    @Test
    void shouldShowLogoutMessageAfterLogout() {
        // Configurar usuario no autenticado después de logout
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        // Ejecutar
        String viewName = loginController.login(null, "true", model);

        // Verificar
        assertEquals("login", viewName);
        verify(model).addAttribute("message", "You have logged out successfully");
    }

    @Test
    void shouldHandleExceptionsGracefully() {
        // Configurar que se lance una excepción
        when(securityContext.getAuthentication()).thenThrow(new RuntimeException("Security context error"));

        // Ejecutar
        String viewName = loginController.login(null, null, model);

        // Verificar
        assertEquals("login", viewName);
        verify(model).addAttribute(eq("error"), contains("An error occurred during login"));
    }

    @Test
    void shouldReturnHomeView() {
        // Ejecutar
        String viewName = loginController.home();

        // Verificar
        assertEquals("welcome", viewName);
    }

    @Test
    void shouldNotShowErrorOrLogoutMessageWhenNoParameters() {
        // Configurar usuario no autenticado
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        // Ejecutar
        String viewName = loginController.login(null, null, model);

        // Verificar
        assertEquals("login", viewName);
        verify(model, never()).addAttribute(any(), any());
    }

    @Test
    void shouldHandleAnonymousUser() {
        // Configurar usuario anónimo
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("anonymousUser");

        // Ejecutar
        String viewName = loginController.login(null, null, model);

        // Verificar
        assertEquals("login", viewName);
        verify(model, never()).addAttribute(any(), any());
    }
}
