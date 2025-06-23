package com.aspiresys.fp_micro_authservice.user;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.aspiresys.fp_micro_authservice.user.role.Role;
import com.aspiresys.fp_micro_authservice.user.role.RoleRepository;

@RestController
@RequestMapping("/auth/api")
public class RegisterController {
    @Autowired
    private AppUserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private RoleRepository roleRepository;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody AppUser user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Usuario ya existe");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        Role defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Rol por defecto no encontrado"));
        user.setRoles(Set.of(defaultRole)); // Asignar rol por defecto
        userRepository.save(user);
        return ResponseEntity.ok("Usuario registrado exitosamente");
    }
}
