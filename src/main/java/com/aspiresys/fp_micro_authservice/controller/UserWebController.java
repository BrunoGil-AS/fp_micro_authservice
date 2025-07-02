package com.aspiresys.fp_micro_authservice.controller;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.aspiresys.fp_micro_authservice.user.AppUser;
import com.aspiresys.fp_micro_authservice.user.AppUserRepository;
import com.aspiresys.fp_micro_authservice.user.role.Role;
import com.aspiresys.fp_micro_authservice.user.role.RoleRepository;

import lombok.extern.java.Log;

/**
 * Controller responsible for handling user registration web requests.
 * <p>
 * Provides endpoints for displaying the registration form and processing user registration.
 * Handles validation, password encryption, role assignment, and error reporting.
 * </p>
 *
 * <ul>
 *   <li><b>GET /user/register</b>: Displays the user registration form. Redirects authenticated users to the home page.</li>
 *   <li><b>POST /user/register</b>: Processes registration form submission, validates user existence, encrypts password,
 *       assigns default role, saves the user, and handles errors.</li>
 * </ul>
 *
 * Dependencies:
 * <ul>
 *   <li>{@link AppUserRepository} for user persistence and lookup.</li>
 *   <li>{@link PasswordEncoder} for secure password storage.</li>
 *   <li>{@link RoleRepository} for role assignment.</li>
 * </ul>
 *
 * Logging is used to record registration failures.
 */
@Controller
@RequestMapping("/user")
@Log
public class UserWebController {

    @Autowired
    private AppUserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private RoleRepository roleRepository;

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        // Check if user is already authenticated
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
            return "redirect:/"; // Redirect to welcome page if already logged in
        }
        
        model.addAttribute("user", new AppUser());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute AppUser user, Model model) {
        try {
            // Check if user already exists
            if (userRepository.findByUsername(user.getUsername()).isPresent()) {
                model.addAttribute("error", "User already exists");
                // Clear password for security and re-add user object to maintain form data
                user.setPassword("");
                model.addAttribute("user", user);
                log.warning("User registration failed: User already exists with username " + user.getUsername());
                return "register";
            }

            // Encrypt password
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            
            // Assign default role
            Role defaultRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("Default role not found"));
            user.setRoles(Set.of(defaultRole));
            
            // Save user
            userRepository.save(user);
            
            model.addAttribute("success", "User registered successfully. You can now login.");
            
            return "login";
            
        } catch (Exception e) {
            model.addAttribute("error", "Error registering user: " + e.getMessage());
            log.severe("User: " + user.getUsername() + " registration failed: " + e.getMessage());
            // Clear password for security and re-add user object to maintain form data
            user.setPassword("");
            model.addAttribute("user", user);
            return "register";
        }
    }
}
