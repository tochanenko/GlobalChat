package com.tochanenko.beglobalchat.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

public class JwtConfigTest {

    private static final String VALID_SUBJECT = "a695d5ae-e4c3-40fd-b2b8-035a6c6c12a2";

    private final JwtConfig config = new JwtConfig();

    private final SecretKey key = new SecretKeySpec(new byte[32], "HmacSHA256");

    private String createToken(
            Instant expiration,
            String audience,
            String subject,
            String issuer
    ) {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .audience(List.of(audience))
                .issuedAt(Instant.now().minusSeconds(300));

        if (subject != null) claims.subject(subject);
        if (expiration != null) claims.expiresAt(expiration);

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();

        return config.jwtEncoder(key).encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }

    @Test
    void validTokenIsAccepted() {
        String token = createToken(
                Instant.now().plusSeconds(900),
                JwtConfig.AUDIENCE,
                VALID_SUBJECT,
                JwtConfig.ISSUER
        );
        Jwt jwt = config.jwtDecoder(key).decode(token);

        assertThat(jwt.getSubject()).isEqualTo(VALID_SUBJECT);
    }

    @Test
    void expiredTokenIsRejected() {
        String token = createToken(
                Instant.now().minusSeconds(150),
                JwtConfig.AUDIENCE,
                VALID_SUBJECT,
                JwtConfig.ISSUER
        );

        assertThatThrownBy(() -> config.jwtDecoder(key).decode(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void wrongAudienceIsRejected() {
        String token = createToken(
                Instant.now().plusSeconds(900),
                "random-api",
                VALID_SUBJECT,
                JwtConfig.ISSUER
        );

        assertThatThrownBy(() -> config.jwtDecoder(key).decode(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void wrongIssuerIsRejected() {
        String token = createToken(
                Instant.now().plusSeconds(900),
                JwtConfig.AUDIENCE,
                VALID_SUBJECT,
                "random-issuer"
        );

        assertThatThrownBy(() -> config.jwtDecoder(key).decode(token)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    void invalidSubjectIsRejected() {
        String token = createToken(
                Instant.now().plusSeconds(900),
                JwtConfig.AUDIENCE,
                "invalid-user-id",
                JwtConfig.ISSUER
        );

        assertThatThrownBy(() -> config.jwtDecoder(key).decode(token)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    void missingSubjectIsRejected() {
        String token = createToken(
                Instant.now().plusSeconds(900),
                JwtConfig.AUDIENCE,
                null,
                JwtConfig.ISSUER
        );

        assertThatThrownBy(() -> config.jwtDecoder(key).decode(token)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    void missingExpirationIsRejected() {
        String token = createToken(
                null,
                JwtConfig.AUDIENCE,
                VALID_SUBJECT,
                JwtConfig.ISSUER
        );

        assertThatThrownBy(() -> config.jwtDecoder(key).decode(token)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    void wrongSigningKeyIsRejected() {
        String token = createToken(
                Instant.now().plusSeconds(900),
                JwtConfig.AUDIENCE,
                VALID_SUBJECT,
                JwtConfig.ISSUER
        );

        byte[] wrongBytes = new byte[32];
        java.util.Arrays.fill(wrongBytes, (byte) 1);

        SecretKey wrongKey = new SecretKeySpec(wrongBytes, "HmacSHA256");

        assertThatThrownBy(() -> config.jwtDecoder(wrongKey).decode(token)).isInstanceOf(JwtException.class);
    }

}
