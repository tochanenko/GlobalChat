package com.tochanenko.beglobalchat.auth;

public record LoginResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {
}
