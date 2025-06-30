package com.aspiresys.fp_micro_authservice.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            Model model) {
        
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
    }
    
    @GetMapping("/")
    public String home() {
        return "welcome";
    }
}
