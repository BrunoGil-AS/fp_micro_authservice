package com.aspiresys.fp_micro_authservice.user.role;

import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

import jakarta.persistence.ManyToMany;
import com.aspiresys.fp_micro_authservice.user.AppUser;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Represents a user role within the system.
 * Each role defines a set of permissions or authorities (e.g., "ROLE_USER", "ROLE_ADMIN").
 * Used for access control and authorization purposes.
 *
 * Fields:
 * <ul>
 *   <li>id - Unique identifier for the role.</li>
 *   <li>name - Name of the role, typically prefixed with "ROLE_".</li>
 * </ul>
 */
@Entity
@Table(name = "role")
@Getter 
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Role implements GrantedAuthority {
    @Id @GeneratedValue
    private Long id;
    private String name; // e.g., "ROLE_USER", "ROLE_ADMIN"

    @ManyToMany(mappedBy = "roles")
    private Set<AppUser> users; // Users associated with this role, if needed for bidirectional mapping

    @Override
    public String getAuthority() {
        return name; // Return the role name as the authority
    }
}
