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
        model.addAttribute("user", new AppUser());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute AppUser user, Model model) {
        try {
            // Verificar si el usuario ya existe
            if (userRepository.findByUsername(user.getUsername()).isPresent()) {
                model.addAttribute("error", "El usuario ya existe");
                return "register";
            }

            // Encriptar la contraseña
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            
            // Asignar rol por defecto
            Role defaultRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("Rol por defecto no encontrado"));
            user.setRoles(Set.of(defaultRole));
            
            // Guardar usuario
            userRepository.save(user);
            
            model.addAttribute("success", "Usuario registrado exitosamente. Puedes iniciar sesión ahora.");
            
            return "login";
            
        } catch (Exception e) {
            model.addAttribute("error", "Error al registrar usuario: " + e.getMessage());
            return "register";
        }
    }
}
