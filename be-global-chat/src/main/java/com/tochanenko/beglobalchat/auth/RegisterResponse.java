package com.tochanenko.beglobalchat.auth;

import java.util.UUID;

public record RegisterResponse(
        UUID id,
        String username
) {
}

