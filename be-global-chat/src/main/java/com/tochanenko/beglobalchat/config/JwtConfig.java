package com.tochanenko.beglobalchat.config;

import com.tochanenko.beglobalchat.utils.ValidationConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

@Configuration
public class JwtConfig {

    public static final String ISSUER = "global-chat";
    public static final String AUDIENCE = "global-chat-api";

    @Bean
    public SecretKey jwtSigningKey(@Value("${app.jwt.secret-base64}") String secret) {
        byte[] keyBytes = Base64.getDecoder().decode(secret);

        if (keyBytes.length < 32) {
            throw new IllegalArgumentException("JWT secret must contain at least 32 bytes");
        }

        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    @Bean
    public JwtEncoder jwtEncoder(SecretKey key) {
        return NimbusJwtEncoder.withSecretKey(key)
                .algorithm(MacAlgorithm.HS256)
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(SecretKey key) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(ISSUER);

        OAuth2TokenValidator<Jwt> audienceValidator = new JwtAudienceValidator(AUDIENCE);

        OAuth2TokenValidator<Jwt> subjectValidator = jwt -> {
            String subject = jwt.getSubject();
            if (subject == null || !ValidationConstants.UUID_PATTERN.matcher(subject).matches()) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid token", null));
            }
            return OAuth2TokenValidatorResult.success();
        };

        OAuth2TokenValidator<Jwt> expirationValidator = jwt -> {
            if (jwt.getExpiresAt() == null) {
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "Invalid token", null)
                );
            }
            return OAuth2TokenValidatorResult.success();
        };

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                issuerValidator,
                audienceValidator,
                subjectValidator,
                expirationValidator
        ));

        return decoder;
    }
}
