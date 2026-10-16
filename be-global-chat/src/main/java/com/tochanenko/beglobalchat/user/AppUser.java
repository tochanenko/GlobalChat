package com.tochanenko.beglobalchat.user;

import com.tochanenko.beglobalchat.utils.ValidationConstants;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "app_users")
public class AppUser {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true, length = ValidationConstants.MAX_USERNAME_LENGTH)
    private String username;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected AppUser() {}

    public AppUser(String username, String passwordHash) {
        this.id = UUID.randomUUID();
        this.username = username;
        this.passwordHash = passwordHash;
        this.createdAt = Instant.now();
    }

    public UUID getId() { return this.id; }
    public String getUsername() { return this.username; }
    public String getPasswordHash() { return this.passwordHash; }
}
