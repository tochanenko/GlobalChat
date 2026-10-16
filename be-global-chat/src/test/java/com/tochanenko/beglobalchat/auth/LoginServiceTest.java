package com.tochanenko.beglobalchat.auth;

import com.tochanenko.beglobalchat.user.AppUser;
import com.tochanenko.beglobalchat.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class LoginServiceTest {

    private static final String VALID_SUBJECT = "a695d5ae-e4c3-40fd-b2b8-035a6c6c12a2";

    @Mock
    AuthenticationManager authenticationManager;

    @Mock
    UserRepository userRepository;

    @Mock
    JwtEncoder jwtEncoder;

    @InjectMocks
    LoginService loginService;

    @Test
    void validCredentialsReturnAccessToken() {
        var user = new AppUser("test_user", "storedHash");

        when(userRepository.findByUsername("test_user")).thenReturn(Optional.of(user));

        Jwt jwt = mock(Jwt.class);
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        when(jwt.getTokenValue()).thenReturn(VALID_SUBJECT);

        var result = loginService.login(new LoginRequest("test_user", "valid-password"));

        assertThat(result.accessToken()).isEqualTo(VALID_SUBJECT);
        assertThat(result.tokenType()).isEqualTo("Bearer");
        assertThat(result.expiresIn()).isEqualTo(900);

        verify(authenticationManager).authenticate(any(Authentication.class));
    }

    @Test
    void invalidCredentialsReturnUnauthorized() {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> loginService.login(new LoginRequest("test_user", "wrong-password")))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(ex -> {
                    var error = (ResponseStatusException) ex;
                    assertThat(error.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
                });

        verifyNoInteractions(userRepository, jwtEncoder);
    }

}
