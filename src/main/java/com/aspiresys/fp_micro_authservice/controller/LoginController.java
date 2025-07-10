package com.aspiresys.fp_micro_authservice.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import lombok.extern.java.Log;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Controller responsible for handling login and home page requests.
 * <p>
 * Provides endpoints for displaying the login page, handling login errors and logout messages,
 * and redirecting authenticated users to the home page. Also serves the welcome page at the root URL.
 * </p>
 *
 * <ul>
 *   <li><b>/login</b>: Displays the login page, shows error messages for failed authentication,
 *       and displays a logout success message when applicable. Redirects already authenticated users to the home page.</li>
 *   <li><b>/</b>: Serves the welcome page for authenticated users.</li>
 * </ul>
 *
 * <p>
 * Uses Spring Security's {@link org.springframework.security.core.context.SecurityContextHolder}
 * to determine authentication status.
 * </p>
 */
@Controller
@Log
public class LoginController {

    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            Model model) {
        
        try{
            // Check if user is already authenticated
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
                return "redirect:/"; // Redirect to welcome page if already logged in
            }
            
            // Only show error message for actual authentication failures
            if ("true".equals(error)) {
                model.addAttribute("error", "Incorrect username or password");
            }
            
            if (logout != null) {
                model.addAttribute("message", "You have logged out successfully");
            }
            
            return "login";
        }catch (Exception e) {
            log.severe("Login error: " + e.getMessage());
            model.addAttribute("error", "An error occurred during login: " + e.getMessage());
            return "login";
        }
    }
    
    @GetMapping("/")
    public String home() {
        return "welcome";
    }
}
