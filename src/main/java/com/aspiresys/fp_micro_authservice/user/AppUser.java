package com.aspiresys.fp_micro_authservice.user;

import java.util.HashSet;
import java.util.Set;

import com.aspiresys.fp_micro_authservice.user.role.Role;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * Entity representing an application user.
 * <p>
 * This class maps to the "app_user" table in the database and contains user credentials
 * and associated roles.
 * </p>
 *
 * <ul>
 *   <li><b>id</b>: Unique identifier for the user (primary key).</li>
 *   <li><b>username</b>: The user's login name.</li>
 *   <li><b>password</b>: The user's hashed password.</li>
 *   <li><b>roles</b>: The set of roles assigned to the user, fetched eagerly.</li>
 * </ul>
 *
 * @author YourName
 */
@Entity
@Table(name = "app_user", uniqueConstraints = @jakarta.persistence.UniqueConstraint(columnNames = "username"))
@Getter 
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class AppUser {
    @Id @GeneratedValue
    private Long id;
    private String username;
    private String password;
    @ManyToMany(fetch = jakarta.persistence.FetchType.EAGER)
    @JoinTable(name = "user_roles",
                joinColumns = @jakarta.persistence.JoinColumn(name = "user_id"),
                inverseJoinColumns = @jakarta.persistence.JoinColumn(name = "role_id"))
    @Builder.Default
    private Set<Role> roles = new HashSet<>();
    
}
