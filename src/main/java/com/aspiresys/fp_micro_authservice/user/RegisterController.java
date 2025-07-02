package com.aspiresys.fp_micro_authservice.user;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.aspiresys.fp_micro_authservice.user.role.Role;
import com.aspiresys.fp_micro_authservice.user.role.RoleRepository;

import lombok.extern.java.Log;

@RestController
@RequestMapping("/auth/api")
@Log
public class RegisterController {
    @Autowired
    private AppUserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RoleRepository roleRepository;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody AppUser user) {
       try{
            // Check if user already exists
            if (userRepository.findByUsername(user.getUsername()).isPresent()) {
                log.warning("User registration failed: User already exists with username " + user.getUsername());
                return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
            }
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            Role defaultRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("Default role not found"));
            user.setRoles(Set.of(defaultRole)); // Assign default role
            userRepository.save(user);
            log.info("User registered successfully: " + user.getUsername());
            return ResponseEntity.ok("User registered successfully");
       } catch (Exception e) {
            log.severe("User registration failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error registering user: " + e.getMessage());
        }
    }
}
