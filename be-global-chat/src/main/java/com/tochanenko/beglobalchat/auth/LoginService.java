package com.tochanenko.beglobalchat.auth;

import com.tochanenko.beglobalchat.config.JwtConfig;
import com.tochanenko.beglobalchat.user.AppUser;
import com.tochanenko.beglobalchat.user.UserRepository;
import com.tochanenko.beglobalchat.utils.ValidationConstants;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Locale;

@Service
public class LoginService {

    public final AuthenticationManager authenticationManager;
    public final UserRepository userRepository;
    public final JwtEncoder jwtEncoder;

    public LoginService(
            AuthenticationManager authenticationManager,
            UserRepository userRepository,
            JwtEncoder jwtEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtEncoder = jwtEncoder;
    }

    public LoginResponse login(LoginRequest request) {
        String username = request.username().toLowerCase(Locale.ROOT);

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    username,
                    request.password()
            ));
        } catch (AuthenticationException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        Instant now = Instant.now();
        long expiresIn = ValidationConstants.JWT_TOKEN_SECONDS_ALIVE_TIME;

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(JwtConfig.ISSUER)
                .subject(user.getId().toString())
                .audience(List.of(JwtConfig.AUDIENCE))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiresIn))
                .claim("username", user.getUsername())
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        return new LoginResponse(accessToken, "Bearer", expiresIn);
    }
}
