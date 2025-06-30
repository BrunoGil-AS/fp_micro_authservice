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

@Controller
@RequestMapping("/user")
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
            return "register";
        }
    }
}
