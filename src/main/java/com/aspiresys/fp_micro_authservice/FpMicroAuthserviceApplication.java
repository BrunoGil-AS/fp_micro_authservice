package com.aspiresys.fp_micro_authservice;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.aspiresys.fp_micro_authservice.user.AppUser;
import com.aspiresys.fp_micro_authservice.user.AppUserRepository;
import com.aspiresys.fp_micro_authservice.user.role.Role;
import com.aspiresys.fp_micro_authservice.user.role.RoleRepository;

@SpringBootApplication
public class FpMicroAuthserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(FpMicroAuthserviceApplication.class, args);
	}
	@Component
	public class DataSeeder implements CommandLineRunner {
		@Autowired AppUserRepository userRepo;
		@Autowired RoleRepository roleRepo;
		@Autowired PasswordEncoder encoder;

		@Override
		public void run(String... args) {
			//Role role = roleRepo.findByName("ROLE_USER").orElseGet(() -> roleRepo.save(new Role(null, "ROLE_USER")));
			Role role = roleRepo.findByName("ROLE_USER").orElseGet(() -> {
				Role newRole = new Role();
				newRole.setName("ROLE_USER");
				return roleRepo.save(newRole);
			});
			AppUser user = userRepo.findByUsernameWithRoles("bruno").orElse(null);
			if (user == null) {
				user = AppUser.builder()
						.username("bruno")
						.password(encoder.encode("1234"))
						.roles(Set.of(role))
						.build();
				userRepo.save(user);
				System.out.println("Default user created: " + user.getUsername());
				
				
			}
			
		}
	}

}
