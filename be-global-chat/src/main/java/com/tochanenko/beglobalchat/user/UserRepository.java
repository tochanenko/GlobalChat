package com.tochanenko.beglobalchat.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<AppUser, UUID> {
    boolean existsByUsername(String username);

    Optional<AppUser> findByUsername(String username);
}
