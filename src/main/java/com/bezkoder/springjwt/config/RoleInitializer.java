package com.bezkoder.springjwt.config;
import java.util.HashSet;
import java.util.Set;

import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RoleInitializer {

    @Autowired
    RoleRepository roleRepository;

    @Bean
    CommandLineRunner initRoles() {
        return args -> {
            Set<Role> roles = new HashSet<>();
            roles.add(new Role(ERole.ROLE_USER));
            roles.add(new Role(ERole.ROLE_ADMIN));
            roles.add(new Role(ERole.ROLE_MODERATOR));

            roles.forEach(role -> {
                if (!roleRepository.existsByName(role.getName())) {
                    roleRepository.save(role);
                }
            });
        };
    }
}
