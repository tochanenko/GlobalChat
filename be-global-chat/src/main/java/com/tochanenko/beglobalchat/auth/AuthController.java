package com.tochanenko.beglobalchat.auth;

import com.tochanenko.beglobalchat.security.LoginRateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;
    private final LoginService loginService;
    private final LoginRateLimiter loginRateLimiter;

    public AuthController(
            AuthService authService,
            LoginService loginService,
            LoginRateLimiter loginRateLimiter
    ) {
        this.authService = authService;
        this.loginService = loginService;
        this.loginRateLimiter = loginRateLimiter;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = this.authService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpServletRequest) {
        String clientIp = httpServletRequest.getRemoteAddr();

        this.loginRateLimiter.check(request.username(), clientIp);

        return this.loginService.login(request);
    }
}
