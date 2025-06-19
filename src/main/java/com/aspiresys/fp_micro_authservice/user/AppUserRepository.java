package com.aspiresys.fp_micro_authservice.user;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository interface for managing {@link AppUser} entities.
 * <p>
 * Extends {@link CrudRepository} to provide basic CRUD operations.
 * </p>
 *
 * <p>
 * Additional query methods can be defined here following Spring Data JPA conventions.
 * </p>
 *
 * @author bruno.gil
 */
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);
    
    @org.springframework.data.jpa.repository.Query("SELECT u FROM AppUser u LEFT JOIN FETCH u.roles WHERE u.username = :username")
    Optional<AppUser> findByUsernameWithRoles(@org.springframework.data.repository.query.Param("username") String username);
}
