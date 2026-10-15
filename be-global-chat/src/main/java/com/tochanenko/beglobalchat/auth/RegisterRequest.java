package com.tochanenko.beglobalchat.auth;

import com.tochanenko.beglobalchat.utils.ValidationConstants;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest (
    @NotBlank
    @Size(
            min = ValidationConstants.MIN_USERNAME_LENGTH,
            max = ValidationConstants.MAX_USERNAME_LENGTH
    )
    @Pattern(regexp = "^[a-zA-Z0-9_]+$")
    String username,

    @NotBlank
    @Size(
            min = ValidationConstants.MIN_PASSWORD_LENGTH,
            max = ValidationConstants.MAX_PASSWORD_LENGTH
    )
    String password
) {}
