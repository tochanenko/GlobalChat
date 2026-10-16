package com.tochanenko.beglobalchat.auth;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
public class MeController {

    @GetMapping("/api/me")
    public Map<String, String> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        String id = jwt.getSubject();
        String username = jwt.getClaimAsString("username");

        if (id == null || username == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token");
        }

        return Map.of("id", id, "username", username);
    }

}
