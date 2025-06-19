package com.aspiresys.fp_micro_authservice.user.role;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

/**
 * Repository interface for accessing and managing {@link Role} entities.
 * Extends {@link CrudRepository} to provide basic CRUD operations.
 *
 * <p>
 * Provides a method to find a role by its name.
 * </p>
 *
 * @author Your Name
 */
public interface RoleRepository extends CrudRepository<Role, Long> {
    Optional<Role> findByName(String name);
}
